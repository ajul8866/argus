# Changelog

## Unreleased

### Changed

- Audit sessions use native Pi/Claude tools in an isolated writable copy. Role
  and harness tool allowlists, shell/writable approvals, and their settings are
  removed. The imported snapshot remains read-only and authoritative for
  evidence quotes.
- Live dashboard refreshes render off-screen and commit only current data, so
  running audits no longer flash loading, reset scroll/focus, or starve updates
  under a continuous event stream.

### Fixed

- HTML reports no longer throw on fenced code blocks.
- Hybrid audits cannot complete before exploration closes and candidates are
  confirmed. Cancelling a running persistence/report task no longer ends as
  completed.
- Verification append-only triggers are restored after the dynamic-schema
  rebuild; nested dependency directories are excluded from inventories.
- Project target rendering, import refresh, and default authorization time
  handling are corrected.


## [0.0.2](https://github.com/ajul8866/argus/releases/tag/v0.0.2) — 2026-10-26

### Changed

- The native installer resolves the newest `vX.Y.Z` release tag instead of a
  hardcoded version, so rerunning the documented command installs the current
  release. `ARGUS_VERSION` pins a specific tag, and README/installation docs
  load the installer from `main`.
- The dashboard now uses the Console system: a graphite ground in three
  lightness steps, hairline panels, Host Grotesk for reading and Atkinson
  Hyperlegible Mono for measured values. Amber marks a person or a decision
  (the current phase, a waiting approval, the primary control); cool blue marks
  an instrument (timestamps, hashes, readings, the selected tab). Figures lead
  each screen in the measured face, and every status label is set in sentence
  case. Faces are self-hosted under `web/src/fonts` (SIL OFL 1.1) and inlined
  into the built stylesheet, so the dashboard makes no font request. No API,
  route or workflow behaviour changed.

### Fixed

- An interrupted fresh install no longer blocks a retry: a missing `VERSION`
  is recovered from `app/package.json`, and an interrupted update restores
  `app.previous` on the next run. The generated launcher sets `umask 077`.
- A failed update keeps the installed release, `data/`, and `app/.env`; the
  new app is built in staging before the swap, and downgrades are refused.
- Writable-workspace policy denials fail closed on the first check. A disabled
  `security.allow_writable_workspace` setting is recorded as
  `writable_workspace_disabled`, and a missing `allow_writable_workspace`
  approval as `writable_workspace_not_approved`. Neither failure is retried.

### Added

- In-place installer updates: the installed release tag and commit are tracked
  in `VERSION` and `REVISION`, and rerunning the installer replaces `app/`
  while preserving `data/` and `app/.env`.
- Opt-in writable audit workspaces for authorized penetration testing. The
  default stays read-only; enabling requires `security.allow_writable_workspace`
  with `confirm_writable_workspace`, a per-audit `writable_workspace` request,
  and a per-task `allow_writable_workspace` approval. The dashboard exposes the
  policy as a confirmation-gated toggle and offers the per-audit request in the
  New audit dialog when enabled. The imported snapshot and quote verification
  remain read-only.

## [0.0.1](https://github.com/ajul8866/argus/releases/tag/v0.0.1) — 2026-10-25

First public release of Argus.

### Added

- Six-phase source audit workflow: mapping, discovery, independent
  confirmation, structured findings, independent reverification, and reports.
- Pi RPC and Claude Code stream adapters with session provenance, bounded
  concurrency, budgets, cancellation, and recovery after interruption.
- Source quote verification, append-only evidence records, and evidence hash
  chains. Deterministic Markdown, JSON, HTML, and PDF reports.
- Automatic discovery of local Skills and MCP configuration from supported
  Pi, Claude, Codex, and OpenCode locations. Role grants, linked MCP servers,
  file previews, availability status, and observed usage history.
- Responsive dashboard for projects, audits, tasks, findings, reports,
  harnesses, Skills, MCP, approvals, and settings.
- Local accounts, role-based access, Argon2id password hashing, CSRF
  protection, and encrypted provider credentials.
- Version-pinned install-and-start script, Docker deployment files, CI,
  contributor documentation, screenshots, and AGPL-3.0-only license.

### Fixed

- Cancelled audits no longer requeue interrupted tasks or accept a late
  successful harness result.
- Failed or cancelled mapping tasks reach a terminal audit state.
- Automatic reverification respects its configured attempt cap.
- Final reports are rebuilt when a later reverification changes the result.

### Current limitations

- Pi or Claude Code and provider credentials are needed for real audits;
  they are configured separately from application installation.
- The native installer supports Linux and macOS; Windows users need WSL2.
- Discovery reports configuration presence, not a live MCP connection.
- OAuth helpers and some native client-specific MCP features are unsupported.
- Source-level reasoning and evidence checks require human review. Runtime
  exploit validation and exhaustive vulnerability coverage are not provided.
