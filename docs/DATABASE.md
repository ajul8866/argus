# Database

SQLite, WAL mode, foreign keys ON, `busy_timeout=5000`, migrations applied
transactionally at startup. Schema lives in `src/db/migrations.ts`; wrapper is
`src/db/index.ts`.

## Entity relationships

```
users 1─* auth_sessions
users 1─* projects (created_by)
projects 1─* repositories
projects 1─* audits
projects 1─* project_targets
repositories 1─* audits
audits 1─* audit_phases (1..6)
audits 1─1 audit_scope_snapshots
users 1─* api_tokens
audits 1─* tasks
audits 1─* agent_sessions
audits 1─* candidates
audits 1─* verifications
audits 1─* findings
audits 1─* evidence
audits 1─* execution_events
audits 1─* reports
tasks *─* tasks via task_dependencies
tasks 1─* agent_sessions (conceptually; task.agent_session_id points at latest)
tasks 1─* evidence
tasks 1─* approvals
candidates *─1 findings (after persistence)
candidates 1─* verifications
findings 1─* verifications
findings 1─* evidence
```

## Tables

### `users`

`id`, unique `email`, `name`, Argon2id `password_hash`, `role` ∈
`admin|auditor|viewer`, `disabled`, `created_at`.

### `auth_sessions`

`id` is SHA-256(token), `user_id`, `csrf_token`, timestamps, IP, user agent.
The raw token lives only in the HttpOnly cookie. Deleting a session revokes it.

### `settings`

Key/value JSON. Defaults are seeded in `src/settings.ts`; updates are validated
against that whitelist and type/range rules. The former
`security.allow_shell_tools`, `security.allow_writable_workspace`, and
`security.require_approval_for_shell` keys are deleted by migration 13.

### `provider_credentials`

`provider`, `env_var`, AES-256-GCM `ciphertext`/`iv`/`tag`, `last4`, timestamps.
Unique `(provider, env_var)`. API never returns the secret.

### `harnesses`

One row per kind (`pi`, `claude-code`): executable, version, status, detail,
capabilities JSON, config JSON, detection timestamps.

### `agent_defs`

Role-primary-keyed. Harness, model, system instructions, max duration, retries,
concurrency, budget, enabled flag. Historical `allowed_tools`, `inherit_tools`,
and shell-flag columns may still exist from earlier migrations; the API no
longer accepts those fields. Roles use the selected harness's native tools.

### `projects`

Source path, scope include/exclude JSON, optional authorizing person and
reference (empty strings when omitted), project concurrency ceiling, status,
creator, timestamps.

### `repositories`

Immutable imported snapshot: project, snapshot path, commit, branch, languages,
frameworks, full inventory JSON (files + hashes + endpoints + auth boundaries +
imports), graph JSON, file count, total bytes, imported timestamp.

### `audits`

Project, optional repository, `mode` (`static|dynamic|hybrid`), optional
`exploration_status` (`not_applicable|open|closing|closed`), `stop_reason`,
`exploration_cost_usd`, status, current phase, config JSON, creator,
timestamps, error. Statuses:
`queued|running|completed|completed_with_errors|failed|cancelling|cancelled`.
`dynamic` audits may have a null `repository_id`.

### `audit_phases`

`(audit_id, phase)` primary key, name, status
`pending|running|completed|blocked|failed|skipped`, timestamps, summary.

### `tasks`

Durable work item: audit, phase, kind, unique `(audit_id, task_key)`, title,
status, priority, payload JSON, result JSON, error/failure kind, agent role,
harness/model, attempts/max, approval requirement/id, latest session id,
deadline, timestamps.

### `task_dependencies`

`(task_id, depends_on_task_id)` primary key. A task is schedulable only when all
dependencies are `completed`.

### `coverage`

Unique `(audit_id, area_id)`, title, status
`PENDING|RUNNING|COMPLETED|BLOCKED|FAILED|NOT_APPLICABLE`, files JSON, task id,
notes, updated timestamp. Includes an `unmapped` pseudo-area.

### `agent_sessions`

Audit, task, role, harness, model, status, workspace path, actual sandbox
mode, harness session reference, PID, exit code, normalized usage JSON,
metadata, timing, error. Each retry gets a new session. The workspace is a
writable copy; the imported snapshot stays read-only.

### `candidates`

Discovery output: optional area, discovery task/session, title, category, CWE,
severity, status
`discovered|confirming|confirmed|refuted|inconclusive|duplicate|persisted`,
finding id, `provenance` (`static|dynamic|hybrid`), optional `link_key`, full
payload JSON. Dynamic-only candidates store `area_id = NULL`.

### `verifications` — append-only

Confirmation or reverification: candidate/finding, kind, agent session,
discovery session, verdict, rationale, evidence check JSON (including
per-excerpt verification results), full payload JSON, timestamp. UPDATE and
DELETE are blocked by triggers.

### `findings`

Code (`ARG-001`), audit/project/candidate, title, category, CWE, severity,
status `confirmed|reverified|rejected|needs_correction|unresolved`, commit,
files JSON (`path`, `start_line`, and `end_line` stored separately, so a
repository-relative path that contains `:` is kept in full), root cause,
preconditions JSON, reproduction JSON, expected,
observed, impact, remediation, discovery/verification/retest session ids,
decisions, timestamps. Provenance columns are immutable by trigger; retest
session may be set once but never changed.

### `evidence` — append-only

Kind, title, content path, content SHA-256, previous chain hash, chain hash,
size, redaction flag, task/session/finding references, timestamp. UPDATE and
DELETE are blocked by triggers. The file content lives under
`$ARGUS_DATA_DIR/evidence/<audit>/<id>.json` with mode 0600.

### `execution_events`

Monotonic per-audit `seq`, type, redacted JSON payload, optional task/session.
Used for SSE replay, task detail, and the audit activity feed. Payloads pass
through the secret redactor before storage.

### `reports`

Audit, format, status, path, SHA-256, size, meta JSON, generated timestamp.

### `approvals`

Audit/task, action, scope, status `pending|approved|denied`, requester,
decider, reason, timestamps. Shell and writable-workspace approvals were
retired by migration 13. The table remains for history; new audits do not
queue those actions.

### `audit_log`

Append-only security log: actor, action, target, detail JSON, IP, timestamp.

### Dynamic tables

| Table | Role |
| --- | --- |
| `project_targets` | Authorized live target: URL, hosts, CIDRs, methods, rps, TLS |
| `target_authorizations` | Who authorized the test window and until when |
| `test_identities` | Test accounts; `secret_ref` points at a `test-identity` credential |
| `audit_scope_snapshots` | Frozen JSON + SHA-256 at start; one per audit |
| `api_tokens` | SHA-256 of the bearer secret, scopes, optional project/audit bind |
| `assets` / `asset_edges` | Project asset graph |
| `exploration_nodes` / `exploration_edges` / `anchors` | Per-audit exploration lineage |
| `retests` | Later dynamic retests of a finding, with their own authorization snapshot |

## Indexes

Audit, task, session, finding, candidate, verification, evidence, event, report,
approval, and auth-session lookups are indexed on their foreign keys/statuses.
Most list endpoints sort by audit + timestamp/phase and are covered by these
indexes.

## Triggers

```sql
evidence_no_update / evidence_no_delete
verifications_no_update / verifications_no_delete
findings_provenance_immutable
audit_scope_snapshots_no_update / audit_scope_snapshots_no_delete
```

The finding trigger blocks changing `audit_id`, `candidate_id`, or replacing an
already-set discovery/verification/retest session id. Scope snapshots are
immutable after audit start.

## Migration policy

- Migrations are ordered by version and applied once in a transaction.
- Never edit an applied migration in an existing deployment; add a new one.
- The test suite runs migrations from scratch and asserts append-only behavior.

## Backup

SQLite backup should include the database plus `evidence/`, `reports/`,
`repos/`, and `master.key` if you did not supply `ARGUS_MASTER_KEY`. Workspaces
are disposable after the audit; snapshots and evidence are not.
