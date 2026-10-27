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
repositories 1─* audits
audits 1─* audit_phases (1..6)
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
against a whitelist and type/range rules.

### `provider_credentials`

`provider`, `env_var`, AES-256-GCM `ciphertext`/`iv`/`tag`, `last4`, timestamps.
Unique `(provider, env_var)`. API never returns the secret.

### `harnesses`

One row per kind (`pi`, `claude-code`): executable, version, status, detail,
capabilities JSON, config JSON, detection timestamps.

### `agent_defs`

Role-primary-keyed. Harness, model, system instructions, allowed tools JSON,
max duration, retries, concurrency, budget, shell flag, enabled flag.
Migration 3 adds `inherit_tools`: inherited roles resolve their tools from the
chosen runtime, including audit overrides. Existing untouched four-tool audit
roles are migrated to inheritance; custom restrictions and legacy shell choices
are preserved. Stored `allowed_tools` remains the explicit list for restricted roles.

### `projects`

Source path, scope include/exclude JSON, optional authorizing person and
reference (empty strings when omitted), project concurrency ceiling, status,
creator, timestamps.

### `repositories`

Immutable imported snapshot: project, snapshot path, commit, branch, languages,
frameworks, full inventory JSON (files + hashes + endpoints + auth boundaries +
imports), graph JSON, file count, total bytes, imported timestamp.

### `audits`

Project, repository, status, current phase, config JSON, creator, timestamps,
error. Statuses: `queued|running|completed|completed_with_errors|failed|cancelling|cancelled`.

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

Audit, task, role, harness, model, status, read-only workspace, actual sandbox
mode, harness session reference, PID, exit code, normalized usage JSON,
metadata, timing, error. Each retry gets a new session.

### `candidates`

Discovery output: area, discovery task/session, title, category, CWE, severity,
status `discovered|confirming|confirmed|refuted|inconclusive|duplicate|persisted`,
finding id, full payload JSON (includes platform discovery excerpt checks).

### `verifications` — append-only

Confirmation or reverification: candidate/finding, kind, agent session,
discovery session, verdict, rationale, evidence check JSON (including
per-excerpt verification results), full payload JSON, timestamp. UPDATE and
DELETE are blocked by triggers.

### `findings`

Code (`ARG-001`), audit/project/candidate, title, category, CWE, severity,
status `confirmed|reverified|rejected|needs_correction|unresolved`, commit,
files JSON, root cause, preconditions JSON, reproduction JSON, expected,
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
decider, reason, timestamps. A task requiring approval is created as
`waiting_approval` and cannot be claimed until approved.

### `audit_log`

Append-only security log: actor, action, target, detail JSON, IP, timestamp.

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
```

The finding trigger blocks changing `audit_id`, `candidate_id`, or replacing an
already-set discovery/verification/retest session id.

## Migration policy

- Migrations are ordered by version and applied once in a transaction.
- Never edit an applied migration in an existing deployment; add a new one.
- The test suite runs migrations from scratch and asserts append-only behavior.

## Backup

SQLite backup should include the database plus `evidence/`, `reports/`,
`repos/`, and `master.key` if you did not supply `ARGUS_MASTER_KEY`. Workspaces
are disposable after the audit; snapshots and evidence are not.
