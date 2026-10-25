# Security model and limitations

Argus is an offensive-security tool that analyzes source code with autonomous
LLM agents. Use it only on repositories you are authorized to assess.

## Authorization and scope

- A project cannot be created without an authorizing person and reference.
- The source path is canonicalized with `realpath` and checked against
  `ARGUS_ALLOWED_ROOTS` on create/import and again when a workspace/evidence
  file is opened.
- Scope globs are enforced on the normalized relative path before file copy,
  in inventory, in explorer/file APIs, and in excerpt verification. `.` and
  `..` segments are resolved first, and a path that leaves the snapshot is
  rejected, so an exclude cannot be bypassed with a dotted path. Prompt text
  is never the authorization boundary.
- Only regular files are imported. Symlinks are skipped during inventory and
  removed from git-archive snapshots before that snapshot is stored. File
  reads do not follow a final symlink, and a file whose resolved location
  differs from the normalized path is rejected. Files larger than the cap are
  skipped and recorded.
- An immutable snapshot is created at import, so later edits to the original
  worktree cannot change what the evidence refers to.

## Execution isolation

- Each task gets a fresh read-only workspace copy containing only in-scope
  files.
- Each session gets a sanitized runtime home. Host credential files are not
  mounted into the sandbox.
- With Bubblewrap available, the harness runs in new PID/IPC/UTS namespaces with
  a cleared environment, a tmpfs `/tmp`, read-only system/harness mounts, and a
  read-only workspace. Host `$HOME`, Argus data, and other repositories are
  hidden.
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
  file, verified against the snapshot. LLM agreement alone is insufficient.

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
- Any role with shell tools causes tasks to be created in
  `waiting_approval`; an administrator must decide. Denial cancels the task.
  There is no implicit approval and no fallback to an unrestricted mode.
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
