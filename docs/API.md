# HTTP API

Base path `/api`. JSON in/out unless noted. Auth uses the `argus_session`
HttpOnly cookie. Mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) require
`x-csrf-token` from `GET /api/auth/me` or the login response. Errors are
`{"error":{"code":"...","message":"...","details":...}}`.

Roles: `viewer` read-only, `auditor` can create/import/run/generate, `admin`
can also configure harnesses/settings/credentials/users and decide approvals.

## Public

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Liveness/version |
| `POST` | `/api/auth/login` | `{email,password}` → sets cookie, returns user+csrf |
| `GET` | `/api/auth/me` | Current user + CSRF |
| `POST` | `/api/auth/logout` | Revoke current session |
| `POST` | `/api/auth/password` | `{current_password,new_password}` |

Login failures are rate limited per IP+email (15-minute window, lock after six
failures).

## Overview

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/overview` | Counts, recent audits/events, findings/coverage mix, harness state |
| `GET` | `/api/events/stream` | Global SSE stream |

## Projects and repositories

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/projects` | any | Project registry with counts |
| `POST` | `/api/projects` | auditor | Create authorized project |
| `GET` | `/api/projects/:id` | any | Project + snapshots + audits |
| `PUT` | `/api/projects/:id` | auditor | Update metadata/scope/status |
| `DELETE` | `/api/projects/:id` | admin | Delete only if no audits |
| `POST` | `/api/projects/:id/import` | auditor | Import current worktree or `{ref}` |
| `GET` | `/api/repositories` | any | All snapshots |
| `GET` | `/api/repositories/:id` | any | Snapshot + inventory + architecture map |
| `GET` | `/api/repositories/:id/tree?path=` | any | Inventory-derived tree |
| `GET` | `/api/repositories/:id/file?path=` | any | Scoped text preview |

Creating a project requires `name`, `source_path`, `authorized_by`,
`authorization_ref`; scope arrays default to `["**/*"]` and the safe exclusion
set. The source path must resolve under `ARGUS_ALLOWED_ROOTS`.

Import writes an immutable snapshot under `$ARGUS_DATA_DIR/repos/...`, records
the commit/ref, and rejects empty/invalid snapshots.

## Audits and tasks

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/audits?project_id=` | any | Audit list |
| `POST` | `/api/audits` | auditor | `{project_id,repository_id?,overrides?}` |
| `GET` | `/api/audits/:id` | any | Phases, coverage, counts, sessions, reports, evidence chain |
| `POST` | `/api/audits/:id/start` | auditor | Start the six-phase workflow |
| `POST` | `/api/audits/:id/cancel` | auditor | Stop active/queued work |
| `GET` | `/api/audits/:id/tasks` | any | Task table |
| `GET` | `/api/audits/:id/sessions` | any | Agent session history |
| `GET` | `/api/audits/:id/findings` | any | Findings |
| `GET` | `/api/audits/:id/events?after=` | any | Event replay |
| `GET` | `/api/audits/:id/stream?after=` | any | Audit SSE stream |
| `GET` | `/api/audits/:id/evidence` | any | Evidence metadata + chain verification |
| `GET` | `/api/audits/:id/reports` | any | Report history |
| `POST` | `/api/audits/:id/reports` | auditor | `{formats?}`; default all four |
| `GET` | `/api/tasks?audit_id=&status=` | any | Cross-audit task queue |
| `GET` | `/api/tasks/:id` | any | Full task, result, dependencies, events, session, evidence |
| `POST` | `/api/tasks/:id/retry` | auditor | Requeue failed/cancelled/blocked |
| `POST` | `/api/tasks/:id/cancel` | auditor | Cancel queued or active task |

Audit overrides: `max_areas`, `max_candidates_per_area`, `max_confirmations`,
`max_reverifications`, `max_concurrent_agents`,
`require_distinct_harness_for_retest`, `max_cost_usd`, `harness_overrides`, and
`writable_workspace`. `writable_workspace: true` is rejected unless
`security.allow_writable_workspace` is already enabled; it makes every harness
task require an `allow_writable_workspace` approval.

Task result shape for agent tasks:

```json
{
  "data": { "...validated phase schema..." },
  "meta": {
    "session_id": "...",
    "harness": "pi",
    "model": "...",
    "session_ref": "...",
    "usage": { "...": "..." },
    "sandbox": "bwrap",
    "started_at": "...",
    "ended_at": "..."
  }
}
```

## Findings and evidence

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/findings?audit_id=&status=` | any | Finding list |
| `GET` | `/api/findings/:id` | any | Finding + candidate + verifications + evidence + sessions |
| `POST` | `/api/findings/:id/retest` | auditor | Queue a fresh independent retest |
| `GET` | `/api/evidence/:id` | auditor/admin | Evidence metadata + content |

Findings are only created by Phase 4 from a `CONFIRMED` verification whose
excerpts were verified by the platform. Reverification history is immutable.

## Harnesses and agents

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/harnesses` | any | Detect both; return status/config/models |
| `GET` | `/api/harnesses/:kind` | any | Detection for `pi|claude-code` |
| `PUT` | `/api/harnesses/:kind` | admin | Save executable/model/permissions/tools |
| `POST` | `/api/harnesses/:kind/check` | auditor | Real auth/health check |
| `POST` | `/api/harnesses/:kind/test` | admin | Real minimal agent invocation |
| `GET` | `/api/harnesses/:kind/models` | any | Detected model list |
| `GET` | `/api/agents` | any | Role definitions |
| `PUT` | `/api/agents/:role` | admin | Harness/model/tools/limits/enabled |

Harness config `env` values are redacted in reads. Secret-looking values must be
stored through `/api/credentials`, not harness env. `bypassPermissions` and
`dangerously-skip-permissions` are rejected.

## Settings, users, approvals

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/settings` | any | Settings and runtime posture; credential metadata only for admins |
| `PUT` | `/api/settings` | admin | Whitelisted settings; enabling shell requires `confirm_shell:true`; enabling writable workspaces requires `confirm_writable_workspace:true`; `security.sandbox_mode` accepts `auto`, `bwrap`, or `none` |
| `GET` | `/api/credentials` | admin | Metadata only |
| `PUT` | `/api/credentials` | admin | `{provider,env_var,value}`; encrypted |
| `DELETE` | `/api/credentials/:id` | admin | Delete |
| `GET` | `/api/users` | admin | List users (no hashes) |
| `POST` | `/api/users` | admin | Create user |
| `PATCH` | `/api/users/:id` | admin | Role/disable/name |
| `GET` | `/api/approvals?status=` | any | Approval queue/history |
| `POST` | `/api/approvals/:id/decide` | admin | `{approved,reason}` |
| `GET` | `/api/reports?audit_id=` | any | Report metadata |
| `GET` | `/api/reports/:id/download` | any | Download generated file |
| `GET` | `/api/audit-log` | admin | Security log |

## SSE

`GET /api/audits/:id/stream?after=<seq>` and `/api/events/stream` return
`text/event-stream`. Each message is a JSON `LiveEvent`:

```json
{
  "id": 123,
  "auditId": "...",
  "taskId": "...",
  "sessionId": "...",
  "seq": 42,
  "type": "task.completed",
  "payload": { "...": "..." },
  "createdAt": "..."
}
```

The audit stream replays missed events after `after`. Heartbeats keep proxies
alive. The UI treats REST as authoritative and uses SSE only to schedule
refreshes.

## Example

```bash
# login
curl -c cookies.txt -H 'content-type: application/json' \
  -d '{"email":"admin@argus.local","password":"..."}' \
  http://localhost:8787/api/auth/login

# create + start
curl -b cookies.txt -H 'content-type: application/json' -H "x-csrf-token: $CSRF" \
  -d '{"project_id":"...","overrides":{"max_areas":2}}' \
  http://localhost:8787/api/audits
curl -b cookies.txt -H 'content-type: application/json' -H "x-csrf-token: $CSRF" \
  -d '{}' http://localhost:8787/api/audits/<id>/start
```
