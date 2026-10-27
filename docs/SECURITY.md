# Security model and limitations

Argus is an offensive-security tool that analyzes source code with autonomous
LLM agents. Use it only on repositories you are authorized to assess.

## Authorization and scope

- Project creation requires a name and repository path. Authorizing person and
  reference are optional metadata; existing records retain their values. The
  dashboard does not request them, and missing values are not filled with
  invented authorization claims. Authentication, role checks, CSRF protection,
  and source-path boundaries still apply.
- Without an explicit `ARGUS_ALLOWED_ROOTS`, Argus detects readable source
  locations from the host user's home, application folder, common project
  locations, temporary directory, and mounted volumes. Administrators may
  restrict them by setting `ARGUS_ALLOWED_ROOTS`. Imported snapshots under
  `<dataDir>/repos` remain included in either mode.
- Folder browsing, project creation, import, workspace copies, and evidence
  reads pin the source path by walking each component without following a
  symlink. The pinned path must sit under an allowed source location.
  Configured locations are canonicalized when they are detected. The source
  path is not passed through `realpath`, because that would follow a symlink
  and authorize its target. A repository symlink is rejected even when that
  target remains inside an allowed location. Folder browsing requires the
  auditor role, returns directory metadata only, and omits hidden folders,
  `node_modules`, and symlinks.
- Scope globs are enforced before file copy, in inventory, in explorer/file
  APIs, and in excerpt verification. Prompt text is never the authorization
  boundary.
- Only regular files are imported; symlinks are skipped. Files larger than the
  cap are skipped and recorded. Inventory reads and snapshot copies walk each
  component of the repository path without following a symlink, then open the
  file without following a symlink and without waiting on a pipe. The opened
  descriptor must still be that in-scope path. Replacing the repository
  directory, or an ancestor directory, with a symlink is rejected. The
  filesystem-root directories `/tmp`, `/var`, and `/etc` are followed only when
  they are symlinks to `private/<name>`, which is the macOS layout for those
  directories. A symlink of any other name, or with any other target, is
  rejected. The read stops at the size checked there, and a file whose bytes no
  longer match the inventory is not copied.
- An immutable snapshot is created at import, so later edits to the original
  worktree cannot change what the evidence refers to.
- Git-ref imports resolve the ref once, archive that immutable commit, and copy
  only in-scope regular files into a read-only snapshot. Excluded files,
  oversized files, and symlinks are not retained in the snapshot. The archive
  reads a git directory opened without following a symlink, and that directory
  must stay inside an allowed source location. A `.git` symlink or `gitdir:`
  file is not followed. The git common directory must resolve to that same git
  directory, following a symlink before `..`. A symlinked object store or a
  symlink inside an object store is rejected, including a directory entry that
  is not valid UTF-8. Each multi-pack-index pack name must be one file name in
  that object store, with no path separator. An alternate object directory is
  resolved the way Git resolves it, including a raw byte in a symlink name, and
  that directory, its symlinks, and its nested alternates must stay inside an
  allowed location. A path that enters `/proc` or `/dev/fd` is rejected: those
  locations describe the checking process, not the git process that reads the
  object store. When the source is a subdirectory of a repository, the
  archive contains only that subdirectory.

## Execution isolation

The AI setup page can explicitly assign one runtime to all four audit roles.
This uses that runtime's default model, intersects native read tools with its
configured tool cap, clears per-role shell access, and disables the optional
preference for a different retest runtime for future audits. Validation and
retesting still require fresh sessions; existing audits keep their saved
configuration. No runtime is silently substituted when a CLI is missing.

Settings confirmation is required when shell or writable workspaces transition
from disabled to enabled. Saving unrelated settings, or retaining an already
enabled value, does not ask again. Per-audit and per-task access decisions
continue to apply.

- Each task gets a fresh workspace copy containing only in-scope files. It is
  read-only by default; write access is an explicitly approved opt-in.
- Each session gets a sanitized runtime home. Host credential files are not
  mounted into the sandbox.
- With Bubblewrap available, the harness runs in new PID/IPC/UTS namespaces with
  a cleared environment, a tmpfs `/tmp`, read-only system/harness mounts, and a
  read-only workspace unless that task received an approved writable workspace.
  Host `$HOME`, Argus data, and other repositories are hidden.
- Without Bubblewrap, the session records `sandbox_mode="workspace-copy"` and a
  warning event. The host/container is then the isolation boundary.
- Docker Compose uses the container as the boundary and sets
  `ARGUS_SANDBOX=none` by default because nested namespaces may be unavailable.

The harness process needs provider network access. Argus does not attempt an
OS-level allowlist of provider endpoints. Network boundary is enforced at the
tool layer: no shell, web fetch/search, write, or MCP tools by default. If an
operator enables shell tools, the task requires an explicit approval — but the
shell can then reach anything the sandbox/container allows. Treat this as a
deliberate high-risk expansion, not a safe default.

**Writable workspaces are a gated exception.** For authorized penetration tests
that need scratch space, an administrator can enable
`security.allow_writable_workspace`; the API requires
`confirm_writable_workspace: true`. Enabling the setting alone grants nothing:
the audit must request `writable_workspace` when it is created, and every
harness task in that audit is created in `waiting_approval` with an
`allow_writable_workspace` decision. A task queues only after every pending
decision for it is approved. At task start Argus re-checks the global setting
and the approval. A disabled setting fails the task as
`writable_workspace_disabled`, and a missing or revoked grant fails it as
`writable_workspace_not_approved`. Either denial is terminal on the first
check: the task is not requeued, and the workspace is not silently downgraded
to read-only.
Only the disposable session copy changes: files become 0600 inside a 0700
directory, `ARGUS_SCOPE.json` stays 0400, and the Bubblewrap workspace mount
becomes read-write. The imported repository snapshot stays read-only and quote
verification continues to read from that snapshot, so a writable workspace
cannot rewrite evidence an agent cites. It does not grant write/edit tools or
shell; role tool lists and the separate shell approval still apply. Under
`workspace-copy` mode only file permission bits differ; the host/container
remains the isolation boundary.

Local Skills/MCP discovery reads known client configuration locations without
executing their commands. Skills have no role grants initially. Administrators
can grant a skill to a role and link local MCP servers; only enabled, present
servers linked to that role's loaded skills enter its isolated session config.
MCP definitions and credentials cannot be supplied through the resource API.
The API exposes source paths, transport and non-secret endpoint metadata only.
Skill references reject traversal, symlinks and common credential file names.
MCP servers can have capabilities beyond read-only auditing. Role instructions
retain the prohibition on writes/destructive actions, but a prompt is not an
MCP-side authorization boundary: trust the selected server and enforce its
permissions at the server/container. Native connectivity also remains subject
to Bubblewrap mounts; Argus does not expand host filesystem access to make a
local MCP executable available.

## Agent authority

- The orchestrator, not an agent, decides phases, task creation, dependencies,
  evidence acceptance, and report contents.
- Agent output is untrusted. It is parsed, schema-validated, and evidence-checked
  before any database side effect. Invalid output becomes a task failure.
- Repository content is explicitly labeled untrusted data in system prompts.
  The fixture includes a prompt-injection sentence to exercise this.
- No harness-native subagent is used for orchestration.
- A discovery session cannot validate its own candidate; a retest session cannot
  be either prior session. This is checked in code, not just prompts.
- `CONFIRMED`/`REVERIFIED` requires at least one exact excerpt on an affected
  file, verified against the snapshot. That read rejects a symlink, a pipe, or
  a repository path whose directory or ancestor was replaced by a symlink, and
  it stops at the size checked on the opened file. LLM agreement alone is insufficient.

Residual prompt-injection risk remains: a model could be manipulated into
reporting a false positive or missing an issue. The platform gates reduce the
chance of a false positive becoming a verified finding, but they cannot prove
absence of vulnerabilities. Human review is required.

## Credentials and secrets

- Provider credentials are encrypted with AES-256-GCM. The master key is
  `ARGUS_MASTER_KEY` or a generated `$ARGUS_DATA_DIR/master.key` (0600).
- Credential values are write-only through the API; reads return provider, env
  variable, and last four characters only.
- Harness configuration responses redact environment values.
- Logs/events are passed through a secret redactor. Generated reports are
  redacted, including code excerpts. Evidence files are protected by filesystem
  permissions (0600) and are served only to auditors/admins.
- Redaction is pattern-based and best-effort. It will not catch every custom
  secret format. Do not paste credentials into prompts or source fixtures.

## Approvals and destructive actions

- `security.allow_shell_tools` is false by default. Enabling it requires an
  administrator and a second explicit confirmation.
- Audit roles inherit the runtime's configured tool list unless an administrator
  saves an explicit role restriction. Changes to runtime tools apply to new
  sessions; active sessions keep their existing permissions. Empty lists disable
  native tools rather than falling back to a runtime default.
- When `security.require_approval_for_shell` is enabled, any role with shell tools
  causes tasks to be created in `waiting_approval`; an administrator must decide.
  Denial cancels the task. Execution rechecks global policy and required approval.
  There is no implicit approval and no fallback to an unrestricted mode.
- `security.allow_writable_workspace` is false by default and follows the same
  shape: administrator confirmation, an explicit per-audit request, and a
  per-task `allow_writable_workspace` approval. A task that requests both shell
  tools and write access needs both decisions before it can queue.
- MCP access is an administrator-managed role/skill grant, separate from the
  per-task shell approval mechanism. Access changes are recorded in the audit
  log; observed tool starts retain session/task/role provenance. Discovery does
  not run or probe the configured external services.

## Evidence integrity

- Evidence appends are serialized per audit and hash-chained.
- UPDATE/DELETE triggers protect evidence and verification rows.
- Finding provenance fields are immutable.
- `GET /api/audits/:id/evidence` recomputes the chain and reports the first
  broken record. Reports include the integrity result.
- `GET /api/evidence/:id`, retest prompts, and report excerpts re-read the sidecar
  only when it is a regular file whose metadata, byte length, and content hash
  match the database record. A mismatch fails closed instead of returning or
  quoting the file. The open does not follow a symlink and does not wait when
  the path is a pipe. The sidecar is JSON, so the file may be larger than the
  recorded content; the reader allows for that escaping and rejects anything
  larger. The read itself stops at the size checked on the open file, so a
  later write cannot make it load more than that bound. Report downloads
  recompute the stored size and SHA-256. That open does not follow a symlink
  and does not wait when the path is a pipe. The report read stops at the size
  checked on the open file, so a later write cannot make it load more than
  that bound.
- Database-level protection assumes the attacker does not have write access to
  the SQLite file itself. Full-disk tampering is detectable by the chain only if
  the attacker does not rewrite both content and chain metadata; the chain is
  tamper-evident, not tamper-proof against a root-level host compromise.

## Authentication

- Local accounts only; no OIDC/SAML in this version.
- Argon2id password hashes; 12-character minimum for new passwords.
- Random 256-bit session tokens; only SHA-256(token) is stored.
- HttpOnly, SameSite=Lax cookies; `Secure` when `ARGUS_SECURE_COOKIES=1`.
- CSRF token required on all mutations.
- Login rate limit and audit logging.
- The login throttle uses the socket peer address instead of caller-provided
  forwarding headers.
- Roles are enforced server-side on every route; UI hiding is not a control.
- The last active administrator cannot be disabled or demoted by the API.

## Known residual risks

1. **Model correctness.** Static reasoning can miss framework behavior or
   produce a plausible-but-wrong claim. The evidence gate helps, but human
   review is mandatory.
2. **Prompt injection.** Read-only tools, scope, and validation reduce impact;
   they do not guarantee the model follows policy.
3. **Harness credentials inside the harness process.** A harness must hold a
   provider token to call its model. The read-only agent tools run inside that
   harness process, so in principle a manipulated or malicious agent could try
   to read process environment or harness config. Argus does not mount host
   credential files into the sandbox and passes only the required environment,
   but it cannot make a token invisible to the process that must use it. Use
   scoped, short-lived provider credentials for sensitive engagements and
   monitor provider usage.
4. **Harness permissions.** Claude Code and Pi are third-party runtimes with
   their own update/permission behavior. Review their versions and settings.
5. **Docker sandbox.** Container mode without Bubblewrap is weaker than
   host+Bubblewrap. The UI/API/report record the actual mode, but operators
   should understand the difference.
6. **No live exploitation.** Reproduction is source-level reasoning unless a
   separate authorized runtime test is added. Findings may depend on deployment
   configuration not present in the repository.
7. **Coverage limits.** Caps and area boundaries are deliberate; the report
   lists them. A completed audit is not a proof of exhaustive discovery.
8. **Process restart.** In-flight harness sessions are terminated, not resumed.
   Retried tasks use fresh sessions and retain the failed attempt as history.
9. **Local DB access.** An attacker with write access to the host/DB can alter
   records; the hash chain makes undetected edits hard but not impossible.
10. **Workspace-copy mode.** Without Bubblewrap, read tools can access absolute
    paths visible to the harness process even though the platform only copied
    in-scope files into the workspace. Use `sandbox_mode=bwrap` (which fails
    closed) or a per-engagement container for strict repository boundaries.
    Docker Compose uses the container as its boundary and does not claim
    namespace isolation between authorized repositories mounted inside it.
