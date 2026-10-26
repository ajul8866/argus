# Harness integration

Argus treats Pi and Claude Code as separate execution runtimes with different
protocols, permissions, session semantics, and output formats. Adapters only
normalize the parts the orchestrator needs; unsupported operations are reported
instead of emulated.

## First-time setup

The application installer starts the dashboard without installing a model
runtime. Install the tools you plan to use separately:

| Runtime | Setup | Versions exercised for v0.0.1 |
| --- | --- | --- |
| Pi | [Pi package and setup](https://www.npmjs.com/package/@earendil-works/pi-coding-agent) | 1.3.0 |
| Claude Code | [Official installation guide](https://code.claude.com/docs/en/setup) | 2.1.310 |

Make sure `pi --version` and/or `claude --version` work in the environment
that starts Argus. Use `ARGUS_PI_BIN` and `ARGUS_CLAUDE_BIN` for custom binary
paths. In the dashboard, open **Settings → Open AI setup → Configure** and
select your provider and model. The initial Pi preset may not exist in your
provider's model catalog. Press **Use for audits** to assign that runtime and
its model and configured tools to all four audit roles in one action. Roles
inherit subsequent tool changes automatically; the default four read tools are
not a fixed ceiling. An optional restriction lives in the role's advanced settings.
Only the chosen runtime is
needed; validation still runs in separate sessions. Per-role customization is
available under **Advanced tools → Agents**.

Supply the provider's expected environment variable through Argus
**Settings → Credentials**, or configure the supported harness environment
described below. A token stored only in a CLI's keychain or OAuth file is not
automatically copied into an isolated agent session. Prefer a provider API key
or supported environment token for this release.

The default mixed workflow remains available for users who configure both
runtimes. The connection test is under **Technical details**; it and audit
tasks can call the provider and consume credits.

## Capability matrix

| Capability | Pi | Claude Code |
|---|---|---|
| Detect executable/version | `pi --version` | `claude --version` |
| Authentication check | `pi auth check --provider … --model … --json` | real minimal prompt + JSON schema |
| Model enumeration | `pi --list-models` | Claude Code aliases + host model picker config |
| Process isolation | RPC child process | CLI child process |
| Streaming | JSONL session events | stream-json records |
| Tool events | `tool_execution_start/end` | assistant `tool_use` + user `tool_result` |
| Structured output | prompt + JSON parsing + platform schema validation | `--json-schema` + `structured_output` |
| Session identity | RPC `get_state.sessionId` / CLI resume ref | `--session-id`, `result.session_id` |
| Resume | supported by Pi; not used for audit steps | `--resume`; not used for audit steps |
| Cancellation | RPC `abort`, then terminate | process terminate |
| Cost reporting | usage/cost in message events | `total_cost_usd` in result |
| Permission control | tool allowlist + no built-in toolset | permission mode + allowed/disallowed tools |
| Native subagents | not used | not used |

## Pi adapter (`src/harness/pi.ts`)

### Startup

```
pi --mode rpc --no-session --no-mcp \
   --provider <provider> --model <model> \
   --append-system-prompt <platform+role policy> \
   --no-builtin-tools --tools read,grep,find,ls
```

The executable is resolved with `which` and, under Bubblewrap, with `realpath`
so binding a symlink cannot confuse the managed Pi launcher. The working
directory is the read-only workspace.

The command above is the default with no linked MCP servers. With assigned
local skills, Argus snapshots their text resources under the sanitized HOME
and includes their instructions in the role prompt. Enabled linked servers
are written to that HOME's `.pi/agent/mcp.json`; `--no-mcp` is replaced by
`--no-extensions --extension builtin:mcp`, with direct exposure and explicit
`mcp__argus_<id>__*` tool patterns. `--no-skills`, `--no-context-files`,
`--no-prompt-templates` and `--no-approve` prevent repository-local additions.

### Protocol handling

- Records are framed on LF only, with CRLF tolerated; a custom byte-stream
  splitter avoids `readline` treating U+2028/U+2029 as record boundaries.
- Commands carry an `id`; responses are correlated by `id`, not order.
- The adapter sends `get_state` and then `prompt`.
- `data.disposition === "handled"` means no run started and is a failure.
- Completion is `agent_settled`; `agent_end` is logged but not treated as final.
- `aborted: true` at `agent_settled` marks cancellation.
- Text deltas are streamed; the last authoritative assistant message supplies
  final text.
- On timeout/abort it sends `abort`, waits 1.2s, then terminates and reaps.
- Stderr is collected for diagnostics and never parsed as protocol.
- The final text is parsed as JSON (raw, fenced, or embedded) and then validated
  against the phase schema. Invalid output is a retryable `invalid_output`
  failure.

### Environment and isolation

- A sanitized `HOME` contains `models.json`, a minimal `settings.json`, the
  session-scoped MCP config, and assigned skill snapshots (no host extension
  packages, sessions, or auth file).
- Provider credentials are injected from the platform vault or an explicit
  config. Pi's own OAuth file is not copied into the sandbox.
- With `bwrap`, only the managed Pi launcher/install, the Node runtime, system
  libraries, `/etc` essentials, the sanitized home, and the read-only workspace
  are mounted. `/root` is otherwise absent.

## Claude Code adapter (`src/harness/claude.ts`)

### Startup

```
claude -p <prompt> \
  --output-format stream-json --verbose \
  --permission-mode plan --permission-prompts none \
  --strict-mcp-config --mcp-config '{"mcpServers":{}}' \
  --append-system-prompt <platform+role policy> \
  --session-id <uuid> \
  --tools Read,Grep,Glob,LS \
  --allowedTools Read,Grep,Glob,LS \
  --disallowedTools Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch \
  --json-schema <schema>
```

`--model`, `--max-budget-usd`, and extra safe arguments are added when configured.
Permission-bypass modes/arguments are rejected by the API.

The implementation passes a mode-0600 MCP configuration file inside the
sanitized HOME, rather than credentials in command-line JSON. It contains only
enabled servers linked to the session's assigned skills, or an empty server
object when none are assigned. `--strict-mcp-config` excludes other MCP config;
`--disable-slash-commands` prevents implicit native skill loading. The tool
allowlist adds only the selected server namespaces.

### Event handling

- `system` records provide the session init.
- `assistant` records yield text/thinking/tool_use blocks.
- `user` records yield tool results.
- `result` is the completion record:
  - `structured_output` is the phase result;
  - `is_error`/`subtype=error` fails the run;
  - `permission_denials` are logged;
  - `usage` and `total_cost_usd` normalize to the shared usage type.
- Non-zero exit or missing result fails the run.
- Cancellation kills the process; the result is marked `cancelled`, not retried
  as a success.
- `stderr` is collected; stream records come only from stdout.

### Credentials

Claude Code's authentication is part of the harness, not the orchestrator.
Argus inherits the harness's existing auth by reading the host
`~/.claude/settings.json` `env` allowlist (`ANTHROPIC_*`, `CLAUDE_CODE_*`) and
passes those variables only to the child process. Platform-stored credentials
with matching env names can override/augment this.

The sandboxed `HOME` contains only a minimal `.claude/settings.json`; host
credential files are not mounted. This means file-based keychain auth may not
work in `bwrap` mode — use environment/API-token auth or platform credentials.

## Health and test connections

- **Check** calls the adapter `health()`: Pi uses its auth check; Claude runs a
  minimal real prompt with JSON schema. Results are persisted.
- **Test** additionally runs a minimal real task and returns structured output,
  usage, sandbox mode, and duration. This consumes provider credits and is
  labeled as a real invocation in the UI.

## Failure classification

`harness_missing`, `harness_auth`, `harness_error`, `agent_error`, `timeout`,
`cancelled`, `invalid_output`, `budget_exceeded`, `internal`, `server_restart`.

Retries are bounded by the role's `max_retries` and are skipped for auth,
missing-harness, cancellation, and budget failures. A failed task becomes a
recorded coverage/reverification limitation; Argus does not pretend it ran.

## Independence

Each agent task creates a new session, new workspace, and new harness runtime
home. The discovering session is compared to the validation session, and both
are compared to the retest session. A violation aborts the task. Harness
diversity is configurable and recorded, but is not itself treated as proof of
independence.
