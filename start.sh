#!/usr/bin/env bash
set -euo pipefail

app_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ $# -ne 0 ]]; then
  printf 'Usage: bash start.sh\nConfigure Argus with .env or ARGUS_* environment variables.\n' >&2
  exit 1
fi

if command -v bun >/dev/null 2>&1; then
  bun_bin="$(command -v bun)"
elif [[ -x "${BUN_INSTALL:-$HOME/.bun}/bin/bun" ]]; then
  bun_bin="${BUN_INSTALL:-$HOME/.bun}/bin/bun"
else
  printf 'Bun >= 1.3.14 is required. Install it from https://bun.com/docs/installation\n' >&2
  exit 1
fi

cd -- "$app_dir"
exec "$bun_bin" run scripts/start.ts
