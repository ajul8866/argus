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

Login failures are rate limited per socket peer address and email (15-minute
window, lock after six failures). `x-forwarded-for` and `x-real-ip` do not
change the throttle bucket.

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
| `POST` | `/api/projects/:id/import` | auditor | Import current worktree or `{ref}`. A ref archive does not follow a `.git` symlink or gitfile. It rejects a git common directory that does not resolve to that git directory, a symlink in an object store, and an alternate Git would resolve outside the allowed roots. An alternate that enters `/proc` or `/dev/fd` is rejected |
| `POST` | `/api/projects/:id/import` | auditor | Import current worktree or `{ref}`. A ref archive does not follow a `.git` symlink or gitfile. It rejects a git common directory that does not resolve to that git directory, a symlink in an object store (including a non-UTF-8 name), a multi-pack-index pack name that leaves that store, and an alternate Git would resolve outside the allowed roots |
| `GET` | `/api/repository-folders?path=&search=&offset=` | auditor | Browse existing host folders, with Git markers and pages of 100 |
| `GET` | `/api/repositories` | any | All snapshots |
| `GET` | `/api/repositories/:id` | any | Snapshot + inventory + architecture map |
| `GET` | `/api/repositories/:id/tree?path=` | any | Inventory-derived tree |
| `GET` | `/api/repositories/:id/file?path=` | any | Scoped text preview. Authorization rejects a repository directory or ancestor that was replaced by a symlink before the preview is read, including when the target remains inside an allowed root. A symlink or pipe in the file path is rejected. The read stops at the checked size and the preview cap |

Creating a project requires only `name` and `source_path`. The optional
`authorized_by` and `authorization_ref` fields remain supported for existing
clients and default to empty strings. Scope arrays default to `["**/*"]` and
the safe exclusion set. Source locations are detected automatically from the
host user's home, the Argus application folder, common project locations, and
mounted volumes. An explicit `ARGUS_ALLOWED_ROOTS` overrides these defaults.
The data directory's `repos` folder is always included for imported snapshots.

The dashboard shows only the project name and repository folder initially.
Browse folders opens a host folder picker. It starts at the host user's home
when available, marks Git repositories, supports filtering and subfolders, and
fills the project name from the selection when the name is empty. No manual
environment configuration is needed with the default source locations.
After creating a project, the dashboard imports its files automatically. An
import failure retains the project and surfaces the error so import can be
retried without creating another project. The raw project API remains separate
from the import endpoint for existing clients.
Description, file patterns, and concurrent agents are under the collapsed
Advanced settings section. Reports omit empty authorization metadata from
Markdown, HTML, and PDF; JSON retains the fields for compatibility.

Folder discovery returns `{path, parent_path, roots, folders, next_offset}`.
Each root has `name` and `path`; each folder also has `is_repository`. The
endpoint returns directory names and paths, never file contents. Hidden
folders, `node_modules`, and symlinks are omitted. Invalid paths, including a
symlink or a symlink ancestor, and invalid offsets return 400. Paths outside
configured locations return 403.

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
| `POST` | `/api/tasks/:id/retry` | auditor | Requeue failed/cancelled/blocked while its audit is running |
| `POST` | `/api/tasks/:id/cancel` | auditor | Cancel queued or active task |

Audit overrides: `max_areas`, `max_candidates_per_area`, `max_confirmations`,
`max_reverifications`, `max_concurrent_agents`, `task_timeout_ms`,
`require_distinct_harness_for_retest`, `max_cost_usd`, `harness_overrides`, and
`writable_workspace`. `max_cost_usd: 0` is a real ceiling: any positive reported
session cost fails the audit. Omit the field or send `null` for no audit-level
cost ceiling. `writable_workspace: true` is rejected unless
`security.allow_writable_workspace` is already enabled; it makes every harness
task require an `allow_writable_workspace` approval.

Project `max_concurrent_agents` must be `null` or an integer from 1 through 16.
Audit concurrency, confirmation, and timeout overrides are validated before
persistence. A task retry against a closed audit returns `409 audit_not_running`;
create a new audit to repeat a closed assessment.

The dashboard inherits server audit defaults and only submits edited overrides.
For a project with no snapshot, it imports files before creating the audit.
When start fails after creation, the saved audit is opened for recovery rather
than leaving a form that could create another audit. Saved snapshots, limits,
cost, deferred start, and enabled write requests are under Advanced audit settings.

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
| `GET` | `/api/evidence/:id` | auditor/admin | Evidence metadata + content. `409 conflict` when the file does not match its database record |

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
| `POST` | `/api/harnesses/:kind/assign` | admin | Explicitly use this runtime for all four audit roles |
| `GET` | `/api/harnesses/:kind/models` | any | Detected model list |
| `GET` | `/api/agents` | any | Role definitions |
| `PUT` | `/api/agents/:role` | admin | Harness/model/tools/limits/enabled |

Harness config `env` values are redacted in reads. Secret-looking values must be
stored through `/api/credentials`, not harness env. `bypassPermissions` and
`dangerously-skip-permissions` are rejected.

`POST /api/harnesses/:kind/assign` atomically assigns the four audit roles to
the selected runtime, clears role-specific model overrides to inherit its model,
enables those roles, and sets `inherit_tools: true` so every tool in the runtime's
configured `allowed_tools` is used. Later runtime tool changes are inherited
automatically. It clears the legacy per-role shell flag and sets `audit.require_distinct_harness_for_retest`
to false for future audits. Existing sessions and audit configurations are not
rewritten. No tool-cap expansion or runtime substitution is performed.

`GET /api/agents` returns each role's resolved `allowed_tools` and `inherit_tools`
boolean. New audit roles inherit runtime tools. `PUT /api/agents/:role` accepts
`inherit_tools: false` with an explicit `allowed_tools` restriction; sending only
`allowed_tools` also opts out of inheritance for compatibility. Sending
`inherit_tools: true` restores automatic inheritance. An empty list means no
native tools. Global shell policy, configured task approvals, workspace write
access, and linked MCP server assignments remain independent controls.

## Settings, users, approvals

| Method | Path | Role | Purpose |
|---|---|---|---|
| `GET` | `/api/settings` | any | Settings and runtime posture; credential metadata only for admins |
| `PUT` | `/api/settings` | admin | Whitelisted settings; newly enabling shell requires `confirm_shell:true`; newly enabling writable workspaces requires `confirm_writable_workspace:true`; `security.sandbox_mode` accepts `auto`, `bwrap`, or `none` |
| `GET` | `/api/credentials` | admin | Metadata only |
| `PUT` | `/api/credentials` | admin | `{provider,env_var,value}`; encrypted |
| `DELETE` | `/api/credentials/:id` | admin | Delete |
| `GET` | `/api/users` | admin | List users (no hashes) |
| `POST` | `/api/users` | admin | Create user |
| `PATCH` | `/api/users/:id` | admin | Role/disable/name |
| `GET` | `/api/approvals?status=` | any | Approval queue/history |
| `POST` | `/api/approvals/:id/decide` | admin | `{approved,reason}` |
| `GET` | `/api/reports?audit_id=` | any | Report metadata |
| `GET` | `/api/reports/:id/download` | any | Download a generated file. A missing file is 404. A symlink, pipe, or size or hash mismatch is 409. The read stops at the recorded size |
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
refreshes. Refreshes are debounced. A refresh that arrives while a dialog
or drawer is open is applied when that overlay closes.

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
