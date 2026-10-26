# Installation

The native installer supports Linux and macOS. On Windows, use WSL2.
You need Bash, Git, curl, and network access to GitHub and the package
registry. The installer resolves and installs the newest `vX.Y.Z` release by
default; set `ARGUS_VERSION` to pin a specific tag. Rerunning it updates an
existing installation in place and preserves its data. Bun 1.3.14 or later is
reused when available. Otherwise, the installer uses
[Bun's official installer](https://bun.com/docs/installation) to install
version 1.3.14 in Argus's private runtime directory; this requires `unzip`.
It does not request `sudo` or modify your shell startup files.

## Install and run

```bash
curl -fsSL https://raw.githubusercontent.com/ajul8866/argus/main/install.sh | bash
```

To download and inspect the installer before running it:

```bash
curl -fsSLo install-argus.sh https://raw.githubusercontent.com/ajul8866/argus/main/install.sh
less install-argus.sh
bash install-argus.sh
```

The default directory is `${XDG_DATA_HOME:-$HOME/.local/share}/argus`:

```text
argus/
├── app/              # Release source, dependencies, and built dashboard
├── data/             # SQLite database, evidence, reports, and keys
├── runtime/          # Bun, when installed by the installer
├── VERSION           # Installed release tag
├── REVISION          # Installed commit
└── start.sh          # Restart command
```

Open http://127.0.0.1:8787. On first start, read `data/bootstrap-admin.txt`
locally, sign in, change the password in Settings, and delete the file.
Its permissions are `0600`. If you provide `ARGUS_ADMIN_PASSWORD` before the
first start, that password is used instead and no bootstrap file is written.
Changing this variable later does not reset an existing account.

Argus runs in the foreground. Press Ctrl+C to stop and use the generated
`start.sh` to restart. The installer does not register a background service.

## Custom paths and ports

Download the installer first, then set options for its invocation:

```bash
ARGUS_INSTALL_DIR="$HOME/apps/argus" ARGUS_PORT=8899 bash install-argus.sh
```

Environment variables before `curl` in a pipeline apply only to `curl`.
When using the pipeline, set options on the `bash` side:

```bash
curl -fsSL https://raw.githubusercontent.com/ajul8866/argus/main/install.sh | ARGUS_PORT=8899 bash
```

To install without starting:

```bash
bash install-argus.sh --no-start
```

Then run:

```bash
ARGUS_PORT=8899 bash ~/.local/share/argus/start.sh
```

For persistent configuration, copy `.env.example` to `.env` inside `app/`
and edit it before starting. The generated launcher supplies the external
data directory; set `ARGUS_DATA_DIR` on the launch command if you need to
override it. Exported variables take precedence over `.env`. The installer
keeps `app/.env` when it updates the application.

| Variable | Default for the standard startup command |
| --- | --- |
| `ARGUS_HOST` | `127.0.0.1` |
| `ARGUS_PORT` | `8787` |
| `ARGUS_DATA_DIR` | Installer: external `data/`; source checkout: `./data` |
| `ARGUS_ADMIN_EMAIL` | `admin@argus.local` |
| `ARGUS_ADMIN_PASSWORD` | Generated on first start when unset |
| `ARGUS_MAX_AGENTS` | `4` |
| `ARGUS_SANDBOX` | `auto`; use `bwrap` to require Bubblewrap isolation |
| `ARGUS_PI_BIN` / `ARGUS_CLAUDE_BIN` | `pi` / `claude` |

See [.env.example](../.env.example) for the remaining options. To import a
local repository outside the application's allowed roots, set
`ARGUS_ALLOWED_ROOTS` to colon-separated authorized directories.

## Harnesses, Skills, and MCP

The application installer does not install Pi or Claude Code, create provider
accounts, or configure credentials. The UI is usable without them; real audits
require configured harnesses. See [harness integration](HARNESSES.md).

Local discovery reads configuration from the server's user home and supported
project directories. Run Argus as the user who owns that configuration.
In a container, only mounted configuration is visible. It cannot read Skills
or MCP files from a visitor's browser or a different machine automatically.

## Troubleshooting

- **Port occupied:** set another `ARGUS_PORT`. Startup exits before initializing
  audit state when the requested address is already bound.
- **Bun download fails:** verify network/proxy access and that `unzip` is
  installed. You can [install Bun yourself](https://bun.com/docs/installation)
  and rerun the installer.
- **Install directory is not empty:** choose a dedicated `ARGUS_INSTALL_DIR`.
  The installer refuses to replace an unrelated directory.
- **Interrupted installation:** rerun the same command. A failed update leaves
  the installed release and data untouched; an interrupted update restores
  `app.previous` on the next run. If `.install-lock` remains after a forced
  termination, confirm the previous installer has stopped before removing it.
- **Downgrade refused:** the installer will not replace a newer release with
  an older one. Back up `data/` and use a separate `ARGUS_INSTALL_DIR` for an
  older release; database migrations are forward-only.
- **Update failed:** fix the reported error and rerun. The previous app stays
  in place until the new build succeeds; `data/` and `app/.env` are kept.
- **Dashboard assets missing:** inside `app/`, run
  `bun install --frozen-lockfile --ignore-scripts` and `bun run build`.
- **Harness missing or authentication failure:** check the Harnesses screen
  and [harness documentation](HARNESSES.md). File-based CLI authentication
  may not work in an isolated session; use the supported environment or vault.
- **Skills or MCP absent:** check supported paths and source diagnostics in
  [local discovery](LOCAL_RESOURCES.md). Missing environment values must be
  available to the Argus server process.

## Updates, backup, and removal

Rerunning the installer resolves the newest release tag. When it differs from
the installed `VERSION`, the installer builds the new app in a staging
directory, swaps it in, and keeps `data/` and `app/.env`. The same release is
reused without rebuilding. Downgrades are refused. Set
`ARGUS_VERSION=vX.Y.Z` to install a specific release.

`VERSION` records the installed release tag and `REVISION` its commit. A
missing `VERSION` is recovered from `app/package.json`, and an interrupted
update restores `app.previous` before the next attempt.

Before changing versions, stop Argus and back up the entire data directory,
including the database, evidence, reports, and `master.key`. If using
`ARGUS_MASTER_KEY`, preserve that value separately. Keep the data backup until
the new instance passes its health check; migrations are forward-only, so
rollback may require restoring that backup. The previous app is not retained
after a successful update.

To remove Argus, stop it and delete its dedicated install directory only after
saving any data you need. Bun installed under `runtime/` is private to Argus;
an existing system or user Bun installation is unaffected.
