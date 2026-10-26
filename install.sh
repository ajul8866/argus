#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_url="https://github.com/ajul8866/argus.git"
version="${ARGUS_VERSION:-}"
install_dir="${ARGUS_INSTALL_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/argus}"
start_after_install=1
staging=""
lock_dir=""
release_tags=""
target_revision=""

info() { printf '[argus] %s\n' "$*"; }
fail() { printf '[argus] %s\n' "$*" >&2; exit 1; }

version_lt() {
  local left=${1#v} right=${2#v} l_major l_minor l_patch r_major r_minor r_patch
  IFS=. read -r l_major l_minor l_patch <<< "$left"
  IFS=. read -r r_major r_minor r_patch <<< "$right"
  if (( 10#$l_major != 10#$r_major )); then
    (( 10#$l_major < 10#$r_major ))
    return
  fi
  if (( 10#$l_minor != 10#$r_minor )); then
    (( 10#$l_minor < 10#$r_minor ))
    return
  fi
  (( 10#$l_patch < 10#$r_patch ))
}

latest_release() {
  local latest="" sha ref tag major minor patch best_major=-1 best_minor=-1 best_patch=-1
  while IFS=$'\t' read -r sha ref; do
    [[ "$ref" == refs/tags/* ]] || continue
    tag=${ref#refs/tags/}
    [[ "$tag" == *'^{}' ]] && continue
    [[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || continue
    major=$((10#${BASH_REMATCH[1]}))
    minor=$((10#${BASH_REMATCH[2]}))
    patch=$((10#${BASH_REMATCH[3]}))
    if (( major > best_major || (major == best_major && minor > best_minor) || (major == best_major && minor == best_minor && patch > best_patch) )); then
      best_major=$major
      best_minor=$minor
      best_patch=$patch
      latest=$tag
    fi
  done <<< "$release_tags"
  printf '%s' "$latest"
}

release_revision() {
  local want=$1 sha ref base="" peeled=""
  while IFS=$'\t' read -r sha ref; do
    if [[ "$ref" == "refs/tags/$want^{}" ]]; then
      peeled=$sha
    elif [[ "$ref" == "refs/tags/$want" ]]; then
      base=$sha
    fi
  done <<< "$release_tags"
  printf '%s' "${peeled:-$base}"
}

build_app() {
  local actual_version
  info "Downloading Argus $version."
  git clone --quiet --depth 1 --branch "$version" -- "$repo_url" "$staging/app"
  (
    cd -- "$staging/app"
    actual_version="$("$bun_bin" -p "require('./package.json').version")"
    [[ "v$actual_version" = "$version" ]] || fail 'The source version does not match the requested release tag.'
    "$bun_bin" install --frozen-lockfile --ignore-scripts
    "$bun_bin" run build
  )
  printf '%s\n' "$version" > "$staging/VERSION"
  printf '%s\n' "$target_revision" > "$staging/REVISION"
}

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
    printf 'Argus installer\n\nUsage: bash install.sh [--no-start]\n\nARGUS_INSTALL_DIR   Installation directory (default: ~/.local/share/argus)\nARGUS_VERSION       Pin a release tag (default: newest vX.Y.Z release)\nARGUS_PORT          Dashboard port (default: 8787)\nARGUS_HOST          Bind address (default: 127.0.0.1)\n\nInstalls the newest Argus release and updates an existing managed installation\nin place while preserving its data directory. Installs missing Bun into the\ninstallation directory. Does not require sudo.\nStarts in the foreground unless --no-start is provided.\n'
    exit 0
    ;;
esac
[[ $# -eq 0 ]] || fail 'Unknown argument. Run: bash install.sh --help'
if [[ -n "$version" ]]; then
  [[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'ARGUS_VERSION must be a release tag such as v0.0.2.'
fi
[[ "$install_dir" = /* ]] || fail 'ARGUS_INSTALL_DIR must be an absolute path.'
case "$(uname -s)" in
  Linux|Darwin) ;;
  *) fail 'The installer supports Linux and macOS. On Windows, run it inside WSL2.' ;;
esac
for dependency in git curl mktemp; do
  command -v "$dependency" >/dev/null 2>&1 || fail "Missing $dependency. Install it with your system package manager and run this command again."
done

release_tags="$(git ls-remote --tags "$repo_url")" || fail "Cannot read release tags from $repo_url."
if [[ -z "$version" ]]; then
  version="$(latest_release)"
  [[ -n "$version" ]] || fail 'No vX.Y.Z release tag was found in the Argus repository.'
fi
target_revision="$(release_revision "$version")"
[[ -n "$target_revision" ]] || fail "Release $version was not found in $repo_url."

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

if [[ ! -e "$install_dir/app" && -e "$install_dir/app.previous" ]]; then
  info 'Restoring the previous application after an interrupted update.'
  mv -- "$install_dir/app.previous" "$install_dir/app"
fi

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
installed_version=""
installed_revision=""
if [[ -f "$install_dir/VERSION" ]]; then
  installed_version="$(cat -- "$install_dir/VERSION")"
fi
if [[ -f "$install_dir/REVISION" ]]; then
  installed_revision="$(cat -- "$install_dir/REVISION")"
fi
if [[ -d "$install_dir/app" ]]; then
  if [[ -z "$installed_version" ]]; then
    installed_version="$(cd -- "$install_dir/app" && "$bun_bin" -p "require('./package.json').version")" || fail 'Cannot read the installed application version from app/package.json.'
    installed_version="v${installed_version#v}"
    info "Recovered the installed version $installed_version from app/package.json."
  fi
  [[ "$installed_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "The installed version '$installed_version' is invalid. Back up the data directory and choose a new ARGUS_INSTALL_DIR."
  if [[ "$installed_version" = "$version" && ( -z "$installed_revision" || "$installed_revision" = "$target_revision" ) ]]; then
    [[ -f "$install_dir/app/web/dist/index.html" ]] || fail 'Dashboard assets are missing. Run bun install --frozen-lockfile --ignore-scripts and bun run build inside the app directory, then run this installer again.'
    printf '%s\n' "$version" > "$install_dir/VERSION"
    printf '%s\n' "$target_revision" > "$install_dir/REVISION"
    [[ ! -e "$install_dir/app.previous" ]] || rm -rf -- "$install_dir/app.previous"
    info "Reusing $version. Existing data and configuration are preserved."
  elif version_lt "$version" "$installed_version"; then
    fail "Refusing to downgrade from $installed_version to $version. Back up the data directory and use a separate ARGUS_INSTALL_DIR if you intend to run an older release."
  else
    info "Updating Argus from $installed_version to $version. The app is rebuilt and $install_dir/data is preserved."
    build_app
    if [[ -f "$install_dir/app/.env" && ! -f "$staging/app/.env" ]]; then
      cp -p -- "$install_dir/app/.env" "$staging/app/.env"
    fi
    rm -rf -- "$install_dir/app.previous"
    mv -- "$install_dir/app" "$install_dir/app.previous"
    if ! mv -- "$staging/app" "$install_dir/app"; then
      mv -- "$install_dir/app.previous" "$install_dir/app"
      fail 'The new application could not be activated; the previous installation was restored.'
    fi
    mv -- "$staging/VERSION" "$install_dir/VERSION"
    mv -- "$staging/REVISION" "$install_dir/REVISION"
    rm -rf -- "$install_dir/app.previous"
    info "Updated to $version."
  fi
else
  build_app
  mv -- "$staging/VERSION" "$install_dir/VERSION"
  mv -- "$staging/REVISION" "$install_dir/REVISION"
  mv -- "$staging/app" "$install_dir/app"
fi

cat > "$install_dir/start.sh" <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
umask 077
base="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
export PATH="$base/runtime/bin:$PATH"
export ARGUS_DATA_DIR="${ARGUS_DATA_DIR:-$base/data}"
exec bash "$base/app/start.sh" "$@"
LAUNCHER
chmod 700 "$install_dir/start.sh"

info "Argus $version is installed in $install_dir"
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
