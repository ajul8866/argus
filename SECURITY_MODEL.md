# Argus threat model

Builds on the repository's own security model, `docs/SECURITY.md` (referenced from root `SECURITY.md` as "the threat model and limitations"), plus `deploy/` (Dockerfile, docker-compose.yml) as the infrastructure. No separate infrastructure repository exists.

## System overview and trust boundaries

Argus is a single-process, self-hosted Bun server (`src/server.ts`) with a SQLite store, a vanilla-TS SPA (`web/src`), and an audit engine that runs third-party LLM agent CLIs (Pi, Claude Code) over imported repository snapshots.

Trust boundaries:
1. **Browser ↔ HTTP API**: cookie session (`argus_session`) + `x-csrf-token` on mutations; roles `viewer < auditor < admin` enforced per route in `src/api/api.ts`.
2. **Host filesystem ↔ Argus import**: `ARGUS_ALLOWED_ROOTS` / auto-detected roots, `realpath` canonicalization, scope globs (`src/repo/*`).
3. **Argus ↔ harness process (agent)**: agents read untrusted repository content; isolation is Bubblewrap (`src/harness/sandbox.ts`) or `workspace-copy` (host/container is the boundary). Agent output is untrusted and schema/evidence-gated (`src/orchestrator/schemas.ts`, `evidence-gate.ts`).
4. **Argus ↔ model providers**: harness holds a decrypted provider credential in its environment (`src/harness/manager.ts`, `src/security/credentials.ts`).
5. **Argus ↔ local Skills/MCP configs**: discovered from disk, granted to roles by admins (`src/local/*`, `src/api/local-resources.ts`).

## Components

| Component | Code | Notes |
|---|---|---|
| **API & Auth** | `src/api/`, `src/auth.ts`, `src/server.ts`, `src/settings.ts` | Routing, sessions, CSRF, roles, users, settings, approvals, credentials API, SSE, static/SPA serving and security headers |
| **Repository Import** | `src/repo/` | Allowed roots, folder browsing, git-ref/path import, scope globs, inventory, workspace copies, scoped file reads |
| **Audit Engine** | `src/orchestrator/` (`engine.ts`, `prompts.ts`, `schemas.ts`, `evidence-gate.ts`, `evidence.ts`) | Phase scheduler, approvals/budgets, agent-output validation, quote gate, hash-chained evidence |
| **Harness Sandbox** | `src/harness/` | Pi/Claude Code adapters, process lifecycle, Bubblewrap / workspace-copy, session homes, MCP/skill session resources |
| **Reports** | `src/reports/` | Markdown/JSON/HTML/PDF generation (headless Chrome), download integrity |
| **Secrets & Local Resources** | `src/security/`, `src/local/`, `src/db/` | AES-256-GCM vault, redaction, Skill/MCP discovery and catalog, SQLite migrations/append-only triggers |
| **Web Dashboard** | `web/src/` | SPA; `h()` DOM helper (no `innerHTML` with untrusted data), CSRF wrapper |
| **Deployment** | `deploy/`, `install.sh`, `start.sh`, `scripts/start.ts`, `.github/workflows/ci.yml` | Installer, Docker image/Compose, CI |

Out of scan scope: `test/fixtures/vulnerable-app/**` (deliberately vulnerable fixture per its README and root `SECURITY.md`; exclude it from security scans).

## Entry points and who can reach them

- **Unauthenticated**: `GET /api/health`, `POST /api/auth/login` (locked out after repeated failures for that socket peer address and email; forwarding headers are not used), static SPA assets.
- **Any authenticated user (viewer+)**: overview, projects/repositories list and detail, repository tree and in-scope file contents (`/api/repositories/:id/tree|file`), audits/tasks/findings/events, per-audit session list, evidence metadata and chain status (`GET /api/audits/:id/evidence`; not sidecar content), SSE stream, reports list and download, approvals list, settings read (includes `allowed_roots` and `data_dir`; credential rows are empty unless admin), harness/agent list, and Skills/MCP reads (`GET /api/skills`, `GET /api/mcp`, skill file preview, usage). Those catalog GETs also refresh on-disk discovery. Skill records include the absolute directory path, and the scan result includes roots. Credential-named skill files are refused.
- **Auditor+**: repository folder browsing (`/api/repository-folders`), project create/update, import, audit create/start/cancel, report generation (`POST /api/audits/:id/reports`), task retry/cancel, finding retest, evidence content (`GET /api/evidence/:id`), harness health check (`POST /api/harnesses/:kind/check`).
- **Admin**: users, credentials, settings write (enabling shell tools or writable workspaces requires a second confirmation), harness config, assign, and connection test, agent role config, approval decisions, audit log, project delete, Skills/MCP grants and rescan. A skill grant does not create a per-task approval. The next session for that role loads the enabled skill and its linked MCP servers.
- **Imported repository content**: reaches agents (prompt injection), the inventory/import code (file names, symlinks, sizes, git refs), and indirectly reports/UI through agent output and excerpts.
- **Local Skill/MCP config files on the host**: parsed by discovery.
- Network exposure: installer/`start.ts` binds `127.0.0.1`; Docker binds `0.0.0.0` and Compose publishes `8787:8787` on all host interfaces with `ARGUS_SECURE_COOKIES=0` by default.

## Assets and sensitivity

1. **Provider credentials** (vault, `master.key`, harness env) — high.
2. **Source code of audited repositories** and any host files reachable outside allowed roots — high (often confidential client code).
3. **Findings, evidence and reports** — high (unpatched vulnerability details of audited systems); integrity matters (hash chain).
4. **Admin sessions / accounts** — high (admin can enable shell tools, writable workspaces, MCP grants → code execution via agents).
5. **Host integrity** — high (harness runs on host or in container; shell tools are opt-in).
6. **Audit availability / provider budget** — medium.

## Attacker profiles

- **A1 Malicious audited repository**: crafted file names/content, symlinks, git refs, prompt injection aimed at agents, XSS payloads in excerpts that flow to UI/reports.
- **A2 Authenticated lower-privilege user** (viewer/auditor) attempting to escalate, read files outside scope, or reach admin-only actions.
- **A3 Network attacker reaching the dashboard** (unauthenticated, CSRF from a malicious site the user visits, or login brute force). On the default localhost deployment this mostly means a malicious website in the operator's browser (CSRF, DNS rebinding, cross-origin reads) or another local process; on Compose, anyone reaching port 8787.
- **A4 Malicious/compromised agent output** (model manipulated by A1) attempting to forge findings, escape the workspace, or exfiltrate credentials.

## Existing controls (from code and `docs/SECURITY.md`)

Argon2id passwords, SHA-256-hashed 256-bit session tokens, HttpOnly SameSite=Lax cookies, CSRF on authenticated non-GET requests, login lockout by socket peer address and email, server-side role checks, last-admin protection; `realpath` + allowed-root checks on browse/import/read; symlinks and oversized files skipped; immutable snapshots; Bubblewrap with `--clearenv` and PID/IPC/UTS namespaces; read-only workspaces by default; shell tools and writable workspaces require an administrator setting plus a per-task approval (`allow_shell_tools` or `allow_writable_workspace`); MCP access is only an administrator skill/server grant and is loaded into the next session with no per-task approval; schema-validated agent output; quote gate against the snapshot; append-only triggers and hash chain; sidecar reads check size/hash and refuse symlinks/pipes; secret redaction; security headers (nosniff, DENY framing, no-referrer, CSP in `src/server.ts`).

## User decisions (answers to threat-model questions)

- **Deployment**: single operator on localhost (installer default, `127.0.0.1`). Docker/Compose exposure is a secondary profile.
- **Attackers in scope**: all of A1 (malicious repository content), A2 (authenticated lower-privilege users escalating), A3 (unauthenticated network attackers reaching the dashboard) and A4 (manipulated agent output). None is ruled out.
- **Residual risks in `docs/SECURITY.md` are NOT accepted**: they are still reported at full severity (workspace-copy mode reach, provider token visible to the harness, host/DB write access, MCP/shell expansion, etc.).
- **Nothing is declared out of scope** besides the deliberately vulnerable fixture `test/fixtures/vulnerable-app/**` (excluded from the scan) and clustered execution (unsupported by design).

## Documented residual risks (reference, not accepted)

`docs/SECURITY.md` lists: model correctness; residual prompt injection; provider token readable by the harness process; third-party harness permissions; Docker mode without Bubblewrap; no live exploitation; coverage caps; in-flight sessions terminated on restart; attacker with host/DB write access; `workspace-copy` mode letting read tools reach absolute host paths; MCP server permissions not enforced by Argus; enabled shell tools reaching anything the sandbox allows.

## Open questions

- Which single asset matters most if forced to choose (provider credentials vs. audited client source vs. findings)?
