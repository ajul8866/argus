# Changelog

## Unreleased

### Fixed

- Writable-workspace policy denials fail closed on the first check. A disabled
  `security.allow_writable_workspace` setting is recorded as
  `writable_workspace_disabled`, and a missing `allow_writable_workspace`
  approval as `writable_workspace_not_approved`. Neither failure is retried.

### Added

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
