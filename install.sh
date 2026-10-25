#!/usr/bin/env bash
set -euo pipefail
umask 077

version="${ARGUS_VERSION:-v0.0.1}"
install_dir="${ARGUS_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/argus}"
start_after_install=1
staging=""
lock_dir=""

info() { printf '[argus] %s\n' "$*"; }
fail() { printf '[argus] %s\n' "$*" >&2; exit 1; }
cleanup() {
  [[ -z "$staging" ]] || rm -rf -- "$staging"
  [[ -z "$lock_dir" ]] || rmdir -- "$lock_dir" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "${1:-}" in
  --no-start) start_after_install=0; shift ;;
  --help|-h)
    printf 'Argus installer\n\nUsage: bash install.sh [--no-start]\n\nARGUS_INSTALL_DIR   Installation directory (default: ~/.local/share/argus)\nARGUS_VERSION       Release tag (default: v0.0.1)\nARGUS_PORT          Dashboard port (default: 8787)\nARGUS_HOST          Bind address (default: 127.0.0.1)\n\nInstalls missing Bun into the installation directory. Does not require sudo.\nStarts in the foreground unless --no-start is provided.\n'
    exit 0
    ;;
esac
[[ $# -eq 0 ]] || fail 'Unknown argument. Run: bash install.sh --help'
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'ARGUS_VERSION must be a release tag such as v0.0.1.'
[[ "$install_dir" = /* ]] || fail 'ARGUS_INSTALL_DIR must be an absolute path.'
case "$(uname -s)" in
  Linux|Darwin) ;;
  *) fail 'The installer supports Linux and macOS. On Windows, run it inside WSL2.' ;;
esac
for dependency in git curl mktemp; do
  command -v "$dependency" >/dev/null 2>&1 || fail "Missing $dependency. Install it with your system package manager and run this command again."
done

mkdir -p -- "$install_dir"
install_dir="$(cd -- "$install_dir" && pwd -P)"
[[ "$install_dir" != / && "$install_dir" != "$HOME" ]] || fail 'Choose a dedicated installation directory.'
if [[ -e "$install_dir/.argus-install" ]]; then
  [[ -f "$install_dir/.argus-install" && "$(cat -- "$install_dir/.argus-install")" = argus-installer-v1 ]] || fail 'The installation marker is invalid. Choose a different ARGUS_INSTALL_DIR.'
else
  shopt -s nullglob dotglob
  existing=("$install_dir"/*)
  shopt -u nullglob dotglob
  [[ ${#existing[@]} -eq 0 ]] || fail 'The installation directory is not empty and is not managed by Argus. Choose a different ARGUS_INSTALL_DIR.'
fi

mkdir -- "$install_dir/.install-lock" 2>/dev/null || fail 'Another installation is in progress. If it was interrupted, remove .install-lock after checking that it has stopped.'
lock_dir="$install_dir/.install-lock"
printf 'argus-installer-v1\n' > "$install_dir/.argus-install"
staging="$(mktemp -d "$install_dir/.install.XXXXXXXX")"

bun_bin=""
for candidate in "$(command -v bun || true)" "$install_dir/runtime/bin/bun" "${BUN_INSTALL:-$HOME/.bun}/bin/bun"; do
  if [[ -n "$candidate" && -x "$candidate" ]] && "$candidate" -e 'process.exit(Bun.semver.satisfies(Bun.version, ">=1.3.14") ? 0 : 1)' >/dev/null 2>&1; then
    bun_bin="$candidate"
    break
  fi
done
if [[ -z "$bun_bin" ]]; then
  command -v unzip >/dev/null 2>&1 || fail 'Installing Bun requires unzip. Install unzip with your system package manager and run this command again.'
  info 'Installing Bun 1.3.14 from bun.com into the private runtime directory.'
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --connect-timeout 15 --max-time 120 https://bun.com/install -o "$staging/bun-install.sh"
  BUN_INSTALL="$install_dir/runtime" SHELL=/bin/sh bash "$staging/bun-install.sh" bun-v1.3.14
  bun_bin="$install_dir/runtime/bin/bun"
  [[ -x "$bun_bin" ]] || fail 'Bun installation did not produce an executable.'
fi

export PATH="$(dirname -- "$bun_bin"):$PATH"
if [[ -e "$install_dir/app" ]]; then
  [[ -f "$install_dir/VERSION" && "$(cat -- "$install_dir/VERSION")" = "$version" ]] || fail 'A different or incomplete app installation exists. Keep its data and choose a new ARGUS_INSTALL_DIR.'
  [[ -f "$install_dir/app/web/dist/index.html" ]] || fail 'Dashboard assets are missing. Run bun install and bun run build inside the app directory.'
  info "Reusing $version. Existing data and configuration are preserved."
else
  info "Downloading Argus $version."
  git clone --quiet --depth 1 --branch "$version" -- https://github.com/ajul8866/argus.git "$staging/app"
  (
    cd -- "$staging/app"
    actual_version="$("$bun_bin" -p "require('./package.json').version")"
    [[ "v$actual_version" = "$version" ]] || fail 'The source version does not match the requested release tag.'
    "$bun_bin" install --frozen-lockfile --ignore-scripts
    "$bun_bin" run build
  )
  mv -- "$staging/app" "$install_dir/app"
  printf '%s\n' "$version" > "$install_dir/VERSION"
fi

cat > "$install_dir/start.sh" <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
base="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
export PATH="$base/runtime/bin:$PATH"
export ARGUS_DATA_DIR="${ARGUS_DATA_DIR:-$base/data}"
exec bash "$base/app/start.sh" "$@"
LAUNCHER
chmod 700 "$install_dir/start.sh"

info "Installed $version in $install_dir"
info "Start again: bash \"$install_dir/start.sh\""
info "First-run credentials: ${ARGUS_DATA_DIR:-$install_dir/data}/bootstrap-admin.txt"
info 'Pi / Claude Code and their provider credentials are configured separately. See README → Configure your agents.'
cleanup
staging=""
lock_dir=""
trap - EXIT INT TERM
if [[ "$start_after_install" -eq 1 ]]; then
  exec bash "$install_dir/start.sh"
fi
