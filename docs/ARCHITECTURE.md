# Architecture

## 1. Shape of the system

```
┌───────────────────────────────────────────────────────────────────────────┐
│                              Web dashboard                                │
│  Vanilla TS SPA · REST + SSE · local session + CSRF                       │
└───────────────▲───────────────────────────────────────────┬───────────────┘
                │                                           │
                │ /api/* (JSON)                             │ /api/events/stream
┌───────────────┴───────────────────────────────────────────▼───────────────┐
│                         Bun HTTP server                                  │
│  auth · API routing · static assets · SSE · redaction · audit log        │
├───────────────────────────────────────────────────────────────────────────┤
│                          Audit orchestrator                               │
│  durable task graph · barriers · scheduler · retries · cancellation      │
│  six phase handlers · coverage · findings · independence checks          │
├───────────────────────────────┬───────────────────────────────────────────┤
│        Harness Manager        │          Evidence + Report               │
│  detection · health · routes  │  SHA-256 chain · append-only rows        │
│  concurrency · timeout        │  Markdown/JSON/HTML/PDF                   │
├───────────────┬───────────────┴───────────────────────────────────────────┤
│ PiAdapter     │ ClaudeCodeAdapter                                         │
│ real RPC      │ real CLI stream-json                                      │
└───────────────┴───────────────────────────────────────────────────────────┘
        │                                   │
   `pi --mode rpc`                  `claude -p ...`
   JSONL stdin/stdout               structured NDJSON
        │                                   │
   Bubblewrap sandbox               Bubblewrap sandbox
   (optional, recorded)             (optional, recorded)
```

## 2. Subsystems

### 2.1 Orchestrator

Owns the workflow. It never delegates phase decisions to a harness-native
subagent mechanism and never sends the whole workflow as one prompt.

- `AuditEngine` (`src/orchestrator/engine.ts`) owns audit lifecycle, task
  creation, barriers, scheduling, retries, cancellation, budgets, coverage,
  candidate/verification/finding persistence, and finalization.
- Tasks are durable rows with a unique `(audit_id, task_key)`, dependencies,
  attempt counters, deadlines, and an assigned role/harness/model.
- One scheduler tick every 1.5s reconciles phase barriers and claims eligible
  queued tasks. Claims use a conditional `UPDATE ... WHERE status='queued'`, so
  duplicate execution is prevented even if reconciliation races.
- Concurrency is bounded by the global setting, the audit config, the project
  ceiling, and each role's `concurrency_limit`.
- A process-local audit lock serializes phase transitions. Scheduler wakeups
  are coalesced, and every completion/failure triggers another reconcile.
- Phase transitions and evidence appends use separate `KeyedSerialQueue`
  instances (`src/concurrency.ts`). Each queue serializes work per audit,
  continues after failures, and releases completed audit keys.

### 2.2 Harness Manager

`src/harness/manager.ts` builds adapters from persisted harness configuration
plus decrypted credential environment. Changing harness config invalidates the
cached adapter. There is no fallback harness: if the assigned harness is missing
or unauthenticated, the task fails and records the reason.

The normalized `HarnessAdapter` surface (`src/harness/types.ts`) supports:

- detect installation, version, models, status
- verify authentication readiness with a real check
- report capabilities and unsupported operations
- create sessions, assign working directories
- execute with prompt, system policy, schema, tools, model, timeout, budget
- stream normalized text/thinking/tool/usage/error events
- cancel/terminate, collect results and harness metadata
- clean up runtime homes and processes
- resume-session fields (not used by the independence workflow)

Results keep harness-specific metadata (`metadata`, `sessionRef`, raw events)
instead of flattening them away.

### 2.3 Six-phase engine

Phase handlers are code, not one prompt:

| Phase | Task kind | Agent? | Persisted output |
|---:|---|---|---|
| 1 | `phase1.map` | mapper | architecture map, areas, coverage matrix |
| 2 | `phase2.discover` per area | researcher | candidates with excerpts + checks |
| 3 | `phase3.confirm` per candidate | validator | immutable verification row, candidate verdict |
| 4 | `phase4.persist` per confirmed candidate | deterministic | finding + evidence records |
| 5 | `phase5.reverify` per finding | retest auditor | immutable reverification row, finding status |
| 6 | `phase6.report` | deterministic | four report records + files |

Barriers prevent Phase 6 until phases 3–5 are terminal. A stale report (created
before a later retest finished) is detected and a rebuild task is scheduled.
Phase 4 and Phase 6 are intentionally deterministic: no model can invent a
finding or report fact.

### 2.4 Two independent real harnesses

#### Pi

- Spawned as `pi --mode rpc --no-session --no-mcp ...` with `cwd` set to the
  read-only workspace.
- Strict JSONL framing: commands in on stdin with unique IDs; responses and
  session events out on stdout; stderr is diagnostics only. Lines are split
  only on LF, never on Unicode separators.
- Completion waits for `agent_settled`; a successful `prompt` response is only
  acceptance. `agent_end` is not treated as completion.
- Tool calls (`tool_execution_start/end`), streamed text/thinking, usage,
  retries, compaction, and abort events are captured and normalized.
- Timeout: sends `abort`, waits, then terminates the process. Cancellation marks
  the session/run cancelled and retries are not silently resumed.
- Model/provider are CLI flags; the adapter passes the configured provider and
  per-role model. Sanitized `HOME` contains only Pi `models.json` and a minimal
  settings file; no extension packages or session persistence.

#### Claude Code

- Spawned as `claude -p <prompt> --output-format stream-json --verbose
  --permission-mode plan --permission-prompts none --strict-mcp-config
  --mcp-config '{"mcpServers":{}}' ...`.
- The prompt is passed as an argument; JSON Schema is enforced with
  `--json-schema`. Structured output is read from `result.structured_output`.
- Assistant text/thinking and tool use/results are normalized from stream
  records. `result` is the completion record; non-zero exit or `is_error`
  fails the task.
- `--allowedTools` is an explicit allowlist; the platform additionally passes
  `--disallowedTools` for Bash/Edit/Write/NotebookEdit/WebFetch/WebSearch when
  not explicitly allowed. Permission bypass flags are rejected.
- Session identity is allocated by Argus. Cancellation kills the process.
- Credentials come from the harness's configured environment (`ANTHROPIC_*`
  keys found in the host Claude settings) or platform-stored credentials.

### 2.5 Evidence and findings

Evidence appends are serialized per audit because the hash chain's
read-previous/write-next section is a critical section. Each record stores:

```
sha256 = SHA-256(content)
prev_hash = previous chain hash or "GENESIS"
chain_hash = SHA-256(prev_hash + ":" + sha256 + ":" + kind + ":" + title)
```

The content file is written mode 0600; DB rows are append-only via triggers.
Verification rows are also append-only. Finding provenance columns are
immutable; retest session can be set once, never changed.

The **platform evidence gate** verifies each cited quote against the repository
snapshot:

- normalize whitespace and strip line-number prefixes
- require a meaningful minimum length
- require the path to be inside the audited scope
- require at least one verified excerpt on an affected candidate/finding file
- downgrade `CONFIRMED`/`REVERIFIED` verdicts that fail the gate

This is the step that makes two agreeing LLMs insufficient.

### 2.6 Reports

`ReportService` reads the database only. It does not call an LLM. It produces:

- Markdown with executive summary, scope, methodology, architecture, coverage,
  limitations, verified findings, source excerpts, evidence hashes, unresolved
  findings, execution history, and final assessment.
- JSON with the same structured data and a stable schema identifier.
- HTML rendered from the redacted Markdown with print styles.
- PDF via headless Chrome when available, otherwise a dependency-free text PDF
  writer. Chrome gets a temporary profile and is stopped once the PDF file is
  complete, because the browser process may not exit on its own. Report bytes
  are hashed and recorded.

## 3. Persistence and recovery

SQLite in WAL mode. Migrations are versioned and applied transactionally.
Foreign keys and check constraints are enabled.

At startup:

- sessions left `starting`/`running` are failed with an interruption reason;
- running tasks are requeued if retry budget remains, otherwise failed;
- queued tasks remain queued;
- running/cancelling audits are reconciled and scheduled again.

The **claim is a recovery marker**, not a distributed lock. Argus is a
single-process coordinator; clustering is out of scope.

## 4. Scope and sandbox flow

`src/repo/import.ts` owns repository import and snapshot persistence; the API
route handles HTTP authorization and audit logging. Inventory and workspace
copying reuse a local scope matcher so each reached glob is compiled once per
operation, preserving include/exclude short-circuit behavior.

1. Project source path is resolved with `realpath` and must be under
   `ARGUS_ALLOWED_ROOTS`.
2. Import builds an inventory using include/exclude globs. Only regular files
   (no symlinks) within scope and size caps are included.
3. A snapshot is copied under `$ARGUS_DATA_DIR/repos/<project>/<id>`. A git
   ref is archived as the resolved commit, symlinks and files outside the
   import scope are removed, and the inventory is rebuilt from that snapshot.
   Built-in excludes match nested directories, not only the repository root.
   A worktree import copies only in-scope regular files.
4. Each task gets a fresh read-only copy under
   `$ARGUS_DATA_DIR/workspaces/<audit>/<session>`.
5. If Bubblewrap is available, the harness runs with a new session, new PID/IPC/
   UTS namespaces, a cleared environment, a tmpfs `/tmp`, read-only system
   binds, a sanitized home, and the workspace as a read-only bind. The host
   home, Argus data, other repositories, and credentials files are not mounted.
6. Otherwise `workspace-copy` mode is recorded with a warning. The container/
   host remains the isolation boundary, and tools remain read-only.

The harness still needs provider network access. Argus enforces network
boundaries at the tool-policy level: no Bash/WebFetch/WebSearch and no MCP by
default. This is a residual risk of LLM harnesses, documented in SECURITY.md.

## 5. UI architecture

Single-page app with a tiny DOM helper, hash router, REST client with CSRF, and
one EventSource for live updates. Pages: Dashboard, Projects, Project detail,
Audits, Audit detail (tasks/findings/coverage/decisions/evidence/reports/
activity/sessions), Explorer (source/architecture/coverage), Harnesses, Agents,
Tasks, Approvals, Findings, Reports, Settings, Login.

All data is fetched from implemented APIs. The UI never fabricates a finding,
task state, harness status, or report. SSE events trigger debounced refresh;
SSE is not the source of truth.

## 6. Request flow example (confirmation)

```
UI POST /api/audits/:id/start
  → AuditEngine.startAudit
  → task phase1.map queued
  → scheduler claims task
  → workspace snapshot copied
  → HarnessManager.run('pi')
  → Pi RPC prompt + agent_settled
  → schema validation
  → handleMap: areas + coverage + phase2 tasks
  → researcher candidates
  → independent validator (claude-code)
  → verifyQuote(repo snapshot) for each excerpt
  → verifications row (append-only)
  → deterministic findings persistence
  → independent retest session
  → final deterministic reports
  → audit completed
```
