# Engineering decisions and intentional scope

## Runtime and stack

**Bun + TypeScript, no runtime dependencies.** Bun provides SQLite, HTTP/SSE,
subprocesses, Argon2id, a test runner, and a bundler. This keeps the self-hosted
surface small and makes the whole system auditable in one language. The brief
preferred Pi RPC for "Go or another non-TypeScript backend"; RPC is still the
correct integration here because it gives process isolation, strict request
correlation, and a language-independent protocol. The adapter does not use a
TypeScript SDK shortcut.

**SQLite over Postgres.** A single-node self-hosted audit platform needs durable
local state and a simple backup. WAL permits concurrent reads; the orchestrator
is single-process. Migrations are explicit and transactional. The schema is
normalized and documented rather than a JSON blob.

**Vanilla TypeScript SPA.** No framework dependency and no build-time magic
beyond Bun's bundler. The UI is fully API-backed, responsive, and accessible
enough for an operator console. The tradeoff is more manual DOM code; the
helper surface stays small.

**Local auth only.** Adding OIDC/SAML without a deployment to test against would
be speculative complexity. Argon2id, HttpOnly cookies, CSRF, rate limiting, and
roles cover the self-hosted case.

## Workflow semantics

**Fresh sessions for independence.** The interface exposes resume, but audit
steps never resume a prior session. A confirmation or retest must not inherit
the discoverer's context. Each task gets a new workspace, session row, harness
runtime home, and captured transcript.

**Confirmation verdicts are not accepted on trust.** The platform verifies
quotes against the imported snapshot and requires an affected-file excerpt.
Without it, a claimed `CONFIRMED` is downgraded to `INCONCLUSIVE`. This is the
central anti-hallucination control.

**Phase 4 is deterministic.** The "Findings Manager" role exists for
configuration completeness, but persistence is code. A model could invent
fields or misstate evidence; deterministic mapping from verified records to the
finding schema avoids that. The workflow is still six executable phases, and
the Phase 4 task is durable and visible.

**Phase 6 is deterministic.** Reports are assembled from the database only. The
brief permits a report-writer agent, but "never invent results" is easier to
guarantee in code. No model is called for report facts. The report writer role
is retained for configuration completeness and disabled by default.

**Caps are explicit.** Areas, candidates, confirmation, and reverification are
bounded. Exceeding the confirmation cap marks candidates `inconclusive` and adds
a limitation rather than pretending they were reviewed.

**Phase 6 gating.** A report cannot be created until phases 3–5 are terminal.
A stale report created before a later retest is detected and rebuilt. The test
suite asserts report creation happens after the last retest.

## Repository handling

**Immutable snapshots.** Import copies only in-scope files into an immutable
snapshot (or `git archive` for a ref) and rebuilds the inventory there. This
prevents a later worktree edit from invalidating evidence. The original commit
and branch are recorded; uncommitted worktree state is represented by the file
hashes in the inventory. A ref archive uses the Git directory discovered for
that work tree and does not pass inherited `GIT_*` overrides through.
Metadata that points at another object store, including a different Git common
directory, is rejected instead of being copied into the snapshot. A promisor
remote is not consulted: lazy fetch is disabled, so a missing object fails the
ref import instead of being downloaded.

**Scope is a platform boundary.** The prompt tells the agent what it is doing,
but the workspace, explorer, and evidence checker independently enforce scope.
Files outside the include globs never enter the snapshot.

**Read-only workspaces by default.** Agents have no write/edit tools by
default. The workspace is also mounted read-only under Bubblewrap. This
deliberately rules out exploit execution and repository mutation. A writable
workspace is a gated exception, not a mode switch: it requires the global
`security.allow_writable_workspace` setting (administrator plus a second
explicit confirmation), a `writable_workspace` request on the individual
audit, and an `allow_writable_workspace` approval for every task. The runtime
re-checks both the setting and the approval at task start and fails the task
closed if either is missing. Only the disposable session copy becomes
writable; the imported snapshot remains the quote-verification source, so
write access cannot forge evidence. Defaults, existing audits, and the
`workspace-copy` host/container boundary are unchanged.

## Harnesses

**No silent substitution.** Role assignment names a harness and model. If that
runtime is missing/unauthenticated, the task fails with a classified failure;
Argus does not quietly run the other harness. Mixed configurations are explicit.

**Native capabilities preserved.** Pi's own agent loop, tools, retries,
compaction, and event stream are used. Claude Code's native CLI loop, tool
permissions, structured output, session identity, and cost reporting are used.
Argus does not reimplement either internal loop.

**Permission policy.** Claude Code is started in `plan` mode with an explicit
tool allowlist and disallowed dangerous tools. Shell tools are off by default.
If enabled, they require a per-task approval. The platform rejects permission
bypass flags.

## Isolation

**Bubblewrap when available.** Local host mode can hide the host home, Argus data,
and other repositories while still allowing provider network access. When
unavailable, the session records `workspace-copy` and a warning; it does not
claim namespace isolation.

**Docker as the boundary.** The Compose deployment uses the container for
isolation and disables Bubblewrap by default because nested user namespaces are
often unavailable. The sandbox mode is a runtime setting (`security.sandbox_mode`)
and a session field; changing it never rewrites prior provenance. Operators who
need the stronger local boundary should run on a host with Bubblewrap and set
`sandbox_mode=bwrap`, which fails closed rather than falling back.

## Explicitly incomplete / deferred

- Harness session resume across server restart (adapter interface supports it;
  the audit workflow intentionally uses fresh sessions).
- OIDC/SAML, multi-tenancy, clustered execution, and distributed locks.
- Live exploit execution and dynamic application testing.
- Automatic SCM synchronization/webhooks.
- Optional agent-written executive narrative is not implemented; the report
  path is deterministic.
- Full network egress allowlisting for harness provider endpoints.
- Redaction of arbitrary custom secret formats beyond the built-in patterns.
