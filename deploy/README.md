# Docker Compose deployment

The image installs Bun, the real Pi coding agent, Claude Code, git, and
bubblewrap. Harness credentials are supplied through environment variables or
the Argus credential vault. They are not baked into the image.

## 1. Prepare

```bash
cp .env.example .env
# set ARGUS_ADMIN_PASSWORD (required) and ARGUS_REPOS_DIR to a directory you are
# authorized to audit. The fixture directory is the default.
docker compose --env-file .env -f deploy/docker-compose.yml build
```

The compose file mounts:

- `argus-data` volume → `/data` (SQLite, evidence, reports, snapshots)
- `${ARGUS_REPOS_DIR}` → `/srv/authorized-repos` (read-only)
- `~/.pi/agent/models.json` → `/root/.pi/agent/models.json` (model catalog only; no credentials)

Harness authentication should be supplied through environment variables
(`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`,
`MCODE_PROVIDER_API_KEY`) or through Argus **Settings → Credentials**. Do not
mount whole host harness config directories into a workspace-copy container:
the agent's read tools could see credential files.

If your harness credentials live elsewhere, adjust the mounts or use Argus
provider credentials in Settings. Never bake API keys into the image.

The Pi model catalog file must exist before starting Compose. If you are not
using Pi, remove that model-catalog mount. Local Skills and MCP discovery inside
Docker sees only files available inside the container; native installation is
the direct option for reusing your existing local configuration.

## 2. Run

```bash
docker compose --env-file .env -f deploy/docker-compose.yml up -d
docker compose --env-file .env -f deploy/docker-compose.yml logs -f argus
```

Open `http://localhost:8787`.

The healthcheck calls `/api/health`. The container drops all Linux capabilities
and sets `no-new-privileges`. Docker Compose sets `ARGUS_SANDBOX=none` by default
because nested Bubblewrap usually fails; the container itself is the isolation
boundary. Session records and reports state the actual mode. If your runtime
supports user namespaces, set `ARGUS_SANDBOX=bwrap` and verify with the harness
page.

## 3. Configure repositories

Set `ARGUS_REPOS_DIR` to the host directory containing authorized repositories.
`ARGUS_ALLOWED_ROOTS` inside the container is `/srv/authorized-repos:/data/repos`.
Create a project with a path under `/srv/authorized-repos`, then import.

## 4. Backup

Back up the named volume `argus-data`. It contains:

- `argus.sqlite` (+ WAL/SHM while running)
- `evidence/`
- `reports/`
- `repos/` (immutable snapshots)
- `master.key` if `ARGUS_MASTER_KEY` was not supplied

Workspaces under `workspaces/` are disposable after execution; snapshots and
evidence are not.

## 5. Local binary instead

For the strongest sandbox on a host with Bubblewrap:

```bash
bun install && bun run build:web
ARGUS_SANDBOX=bwrap bun run start
```

Use the Docker route when nested namespaces are unavailable, and treat the
container plus read-only workspace copies as the boundary.
