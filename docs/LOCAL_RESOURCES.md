# Local Skills and MCP

Argus automatically discovers local skills and MCP definitions. It has no
manual add/upload endpoint for these resources and never edits their source
files. Open **Skills** or **MCP servers** in the Execution navigation.

## Discovery

Skills are read from `~/.agents/skills`, `~/.codex/skills` (including `.system`),
`~/.claude/skills`, `~/.pi/agent/skills`, `~/.config/opencode/skills`, the Codex
plugin cache, and the Argus project's corresponding skill directories.
`SKILL.md` supplies the name, description and instructions. Aliases are
deduplicated by canonical location; byte-identical copies with the same name
are grouped. Source locations remain visible.

MCP definitions come from:

- `~/.pi/agent/mcp.json`
- `~/.claude.json`, including applicable project entries
- `~/.claude/mcp.json` and `~/.config/claude/claude_desktop_config.json`
- `~/.codex/config.toml`
- The Argus project's `.mcp.json`, `.pi/mcp.json`, and `.codex/config.toml`

JSON `mcpServers` and TOML `mcp_servers` are recognized. Equivalent same-name
definitions are grouped; different configurations with the same name retain
separate identities and source information. HTTP endpoint metadata omits
credentials, query strings and paths. Commands/arguments, environment values
and headers are not returned as raw configuration. Configurations stay in
memory and are reread from local files; SQLite stores metadata and access
policy, not their credential values.

Discovery runs on startup and on catalog/session requests with a 15-second
cache. Open catalog pages refresh every 30 seconds. **Rescan local** requests
an immediate scan; it does not register anything manually. Missing resources
remain visible with their assignments and usage history. Invalid JSON/TOML,
unreadable skills and missing environment variables have explicit diagnostics.
Definitions never start a subprocess or make a network request during discovery.

Discovery is bounded to known roots: 5,000 directories, depth 9, and 250 server
definitions per configuration. Skill files are text up to 256 KB. Readable
references are listed up to 512 files/depth 8. Credential files and symlinks
are excluded; reads are confined to the discovered skill directory.

## Agent access

Discovered skills initially have no assigned agent roles. On a skill's detail
page, an administrator selects its agent visibility and linked MCP servers,
then saves access. Settings survive rescans and affect new sessions. Other
signed-in users may inspect the catalog but cannot change grants or force a scan.

Each session loads its enabled, present, assigned skills automatically. The
platform snapshots their text references in a sanitized harness HOME and adds
the instructions to the role prompt. The session limit is 16 skills, 160 KB of
instruction text and 2 MB of text resources per skill. Excess or invalid assigned
configuration fails explicitly before the model is invoked.

Only enabled, present MCP servers linked to those loaded skills are passed to
the harness. Source-disabled servers remain disabled even when enabled in
Argus. Runtime namespaces use stable resource IDs to avoid name collisions.
Pi receives only its session `mcp.json` and explicit tool namespaces; Claude
receives a session config file with `--strict-mcp-config`. Credentials are not
put in the CLI arguments. Harness cleanup removes the temporary home.

Both harnesses support stdio and Streamable HTTP definitions; legacy SSE is
supported by Claude only. Environment references and Codex environment-header
mapping are resolved from Argus's environment. Shell-based substitutions,
fixed server working directories and native OAuth helper configuration are
reported as unsupported rather than executed or silently imported. A local
client's cached OAuth login is not copied into a session. With containers,
the relevant local directories must be visible inside the container. With
Bubblewrap, MCP commands still need their runtime paths inside the sandbox;
Argus does not expose additional host directories automatically.

Detected means configuration was found, not that a remote server is connected.
Connections occur through the harness when a task actually starts. Existing
authorization, source-evidence checks and independent verification remain.
MCP server permissions are a separate trust boundary; see [Security](SECURITY.md).

## Usage and API

Skill **session loads** count harness session-start events with that skill
assigned. MCP **tool calls** count observed tool-start events in granted
namespaces. Call IDs deduplicate repeated events. Statistics include distinct
tasks, last usage and the latest 20 events with role, harness and task provenance.
They do not claim that an operation completed successfully.

| Endpoint | Purpose |
|---|---|
| `GET /api/skills`, `GET /api/mcp` | Catalog, roles, source metadata and scan diagnostics |
| `GET /api/skills/:id` | File index and skill usage |
| `GET /api/skills/:id/file?path=SKILL.md` | Confined text preview |
| `GET /api/mcp/:id` | Server metadata, linked skills and usage |
| `GET /api/skills/:id/usage`, `GET /api/mcp/:id/usage` | Usage statistics and latest events |
| `PUT /api/skills/:id` | Admin: `enabled`, `roles`, `mcp_ids` only |
| `PUT /api/mcp/:id` | Admin: `enabled` only |
| `POST /api/skills/rescan`, `POST /api/mcp/rescan` | Admin: immediate local discovery |

All routes use the existing session authentication; mutations require CSRF
and the administrator role. Access changes are recorded in the audit log.

## Verification

```sh
bun run check
bun run build
bun run scripts/check-local-resources-ui.ts
bun run scripts/check-local-mcp.ts
```

Unit/integration tests use temporary local configurations, real SQLite,
scripted harness events and subprocesses that inspect session configuration.
The engine test proves role selection, instruction injection, evidence metadata
and streamed usage persistence. The native Pi check connects only to a
temporary local MCP fixture; it does not call a model provider. UI validation
uses an isolated Chromium profile and restores the access settings it changes.
The UI script can use `ARGUS_ADMIN_EMAIL`/`ARGUS_ADMIN_PASSWORD`, or the local
bootstrap credential file. Browser snapshots are saved under `/tmp/argus-local-ui`.

Native reference: [Claude Code MCP configuration](https://code.claude.com/docs/en/mcp)
and [CLI options](https://code.claude.com/docs/en/cli-reference). Pi configuration
was checked against the installed 1.3.0 CLI help and MCP implementation.

Validation on 25 October 2026: TypeScript and bundle builds passed; 49 tests
passed with 258 assertions. The running local catalog found 310 skills and
12 MCP entries. Browser checks at 320, 768, 1024 and 1440 px passed with no
body overflow or console errors. One locally unreadable skill and MCP entries
with a missing environment reference remained explicitly flagged; source
configuration was not changed. No real provider audit was started.

During full-suite verification, a deterministic regression test also exposed
an existing report freshness race: a report queued before retest completion
could be treated as stale even when generation began afterwards. Freshness
now compares the generation start time, with creation time as the fallback
for legacy rows. The existing exact report-count assertions remain intact.
