# Security policy

Argus v0.0.2 is the current release. Security fixes are maintained on `main`
and published as new releases. The installer resolves the newest release tag
by default; upgrade to the latest patched version when one is available.

## Report a vulnerability

Use GitHub's [private vulnerability reporting](https://github.com/ajul8866/argus/security/advisories/new)
for vulnerabilities in Argus. Include the affected version, a minimal
reproduction, the expected security boundary, and the observed impact. Use
synthetic credentials and test repositories. Do not publish live tokens,
customer data, or exploit details in a public issue.

Ordinary bugs and feature requests belong in
[issues](https://github.com/ajul8866/argus/issues).

## Operating Argus

Audit repositories you are authorized to assess. Findings require human
review. A completed audit does not establish that a codebase is secure.
The bundled vulnerable application is a test fixture; do not deploy it.

The installer binds to `127.0.0.1` through the standard startup command. Use
HTTPS and `ARGUS_SECURE_COOKIES=1` behind a trusted reverse proxy when exposing
the dashboard. Protect and back up the data directory and encryption key.

Local discovery reads Skills and MCP configuration without starting the
configured MCP servers. Skills receive no role grants initially. Review each
server's capabilities before linking it to a skill and granting that skill to
an agent. MCP-side permissions must enforce any read-only requirement.

Bubblewrap availability changes the isolation boundary. Workspace-copy mode
does not prevent a harness from reading other host paths. Use explicit
`ARGUS_SANDBOX=bwrap` on a supported Linux host or a dedicated container for
strict separation. See [the threat model and limitations](docs/SECURITY.md)
and [deployment guide](deploy/README.md).
