#!/bin/sh
# Install agent-guard from this checkout into the operator's account.
#
# Layout after installation:
#   $AGENT_GUARD_ROOT (default ~/.local/share/agent-guard)   code, pinned Node runtime, config.json, state/
#   $AGENT_GUARD_BIN  (default ~/.local/bin)                  thin wrappers
#
# The checkout is the source of truth; the installed copy additionally holds `state/`
# (isolated homes, imported credentials, review baselines). This script never touches
# `state/` and never overwrites an existing `config.json`.
#
# Every destination is validated before it is written: directories must be real directories
# owned by the caller, and files are published by writing a temporary file next to the
# destination and renaming it over (rename replaces a symlink itself, never its target).
set -eu

REPO="$(cd "$(dirname "$0")" && pwd)"
TARGET="${AGENT_GUARD_ROOT:-$HOME/.local/share/agent-guard}"
BIN="${AGENT_GUARD_BIN:-$HOME/.local/bin}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "agent-guard requires macOS Seatbelt (sandbox-exec); no other platform is supported." >&2
  exit 1
fi

fail() { echo "install.sh: $*" >&2; exit 1; }

# A destination directory must be a real directory owned by the caller (never a symlink).
ensure_dir() {
  if [ -L "$1" ]; then fail "refusing symlinked directory: $1"; fi
  if [ ! -e "$1" ]; then mkdir -p "$1"; fi
  if [ ! -d "$1" ]; then fail "not a directory: $1"; fi
  if [ ! -O "$1" ]; then fail "not owned by you: $1"; fi
}

# publish <source> <destination> <mode>: atomic replacement; refuses to replace a link or non-file.
publish() {
  src="$1"; dst="$2"; mode="$3"
  if [ -L "$dst" ] || { [ -e "$dst" ] && [ ! -f "$dst" ]; }; then fail "refusing to replace a link or non-file: $dst"; fi
  tmp="$dst.tmp.$$"
  cp "$src" "$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$dst"
}

# Refuse an installation root inside a folder the operator might open as a workspace: the confined
# child could then replace the supervisor. agent_guard.py also refuses such workspaces at launch.
case "$TARGET" in
  "$HOME"|"$HOME/Desktop"*|"$HOME/Documents"*|"$HOME/Developer"*|"$HOME/Projects"*|"$HOME/src"*)
    fail "AGENT_GUARD_ROOT must not be inside a project folder (got $TARGET); use the default or a hidden path such as ~/.local/share/agent-guard" ;;
esac

umask 077
ensure_dir "$TARGET"; chmod 700 "$TARGET"
for sub in runtime native tests vendor adapters examples; do ensure_dir "$TARGET/$sub"; done
ensure_dir "$BIN"

# 1. Code. Only reviewed source files; state/ and config.json are left alone.
for file in "$REPO"/*.py "$REPO"/*.mjs "$REPO"/*.cjs "$REPO"/*.swift "$REPO"/LICENSE; do
  publish "$file" "$TARGET/$(basename "$file")" 600
done
chmod 700 "$TARGET/agent_guard.py"
for file in "$REPO"/tests/*.py; do publish "$file" "$TARGET/tests/$(basename "$file")" 600; done
for file in "$REPO"/adapters/*.py; do publish "$file" "$TARGET/adapters/$(basename "$file")" 600; done
publish "$REPO/native/SafeIcon.icns" "$TARGET/native/SafeIcon.icns" 600
for file in "$REPO"/examples/*; do publish "$file" "$TARGET/examples/$(basename "$file")" 600; done
publish "$REPO/runtime/package.json" "$TARGET/runtime/package.json" 600
publish "$REPO/runtime/package-lock.json" "$TARGET/runtime/package-lock.json" 600
rsync -a --no-links --exclude __pycache__ "$REPO/vendor/" "$TARGET/vendor/"

# 2. Node for the supervisor (sandbox_runner.mjs). Pin it in config.json so that a later
#    `nvm install` or `brew upgrade` cannot silently change which binary runs the trusted supervisor.
if [ -L "$TARGET/config.json" ]; then fail "refusing symlinked config.json"; fi
if [ ! -e "$TARGET/config.json" ]; then
  NODE_BIN="${AGENT_GUARD_NODE:-$(command -v node || true)}"
  if [ -z "$NODE_BIN" ]; then fail "no node binary found; install Node 22+ or set AGENT_GUARD_NODE"; fi
  # Record the resolved file, not a Homebrew/nvm alias symlink.
  NODE_BIN="$(/usr/bin/python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$NODE_BIN")"
  NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  if [ "$NODE_MAJOR" -lt 22 ]; then fail "node 22 or newer is required for the pinned sandbox runtime (found $("$NODE_BIN" --version 2>/dev/null || echo unknown))"; fi
  /usr/bin/python3 -c 'import json,sys; print(json.dumps({"node": sys.argv[1]}, indent=2))' "$NODE_BIN" > "$TARGET/config.json.tmp.$$"
  chmod 600 "$TARGET/config.json.tmp.$$"; mv -f "$TARGET/config.json.tmp.$$" "$TARGET/config.json"
fi
NODE_BIN="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node"])' "$TARGET/config.json")"
[ -x "$NODE_BIN" ] || fail "config.json points at a node that is not executable: $NODE_BIN"

# 3. Pinned sandbox runtime (@anthropic-ai/sandbox-runtime + undici) from the lock file.
( cd "$TARGET/runtime" && PATH="$(dirname "$NODE_BIN"):$PATH" npm ci --ignore-scripts --no-audit --no-fund --loglevel=error )

# 4. Native Zcode Safe launcher (optional; only needed for the Zcode desktop integration).
if command -v swiftc >/dev/null 2>&1; then
  ( cd "$TARGET" && swiftc -O -framework AppKit ZcodeSafe.swift -o "native/ZcodeSafeLauncher.tmp.$$" 2>/dev/null \
      && codesign -s - -i local.agentguard.zcode.safe-launcher -f "native/ZcodeSafeLauncher.tmp.$$" >/dev/null 2>&1 \
      && chmod 700 "native/ZcodeSafeLauncher.tmp.$$" && mv -f "native/ZcodeSafeLauncher.tmp.$$" native/ZcodeSafeLauncher ) \
    || echo "note: ZcodeSafe launcher was not built (swiftc failed); Zcode Safe.app is unavailable." >&2
fi

# 5. Wrappers. `-I` keeps the supervisor free of PYTHONPATH/site customisation. The script path is
#    single-quoted so an installation root containing spaces or metacharacters still works.
QUOTED_SCRIPT="$(printf '%s' "$TARGET/agent_guard.py" | sed "s/'/'\\\\''/g")"
write_wrapper() {
  if [ -L "$BIN/$1" ]; then fail "refusing to replace symlinked wrapper: $BIN/$1"; fi
  tmp="$BIN/$1.tmp.$$"
  printf '#!/bin/sh\nexec /usr/bin/python3 -I '"'"'%s'"'"' %s "$@"\n' "$QUOTED_SCRIPT" "$2" > "$tmp"
  chmod 700 "$tmp"; mv -f "$tmp" "$BIN/$1"
}
write_wrapper agent-guard ""
write_wrapper safecode "safecode --"
write_wrapper opencode-safe "opencode"
write_wrapper safekimi "kimi --"
write_wrapper token-usage "usage"

cat <<EOF
agent-guard installed to $TARGET
  node:      $NODE_BIN
  wrappers:  $BIN/{agent-guard,safecode,opencode-safe,safekimi,token-usage}
Next steps:
  1. agent-guard init                         # create state for the agents that are installed, record baselines
  2. agent-guard doctor                       # verify runtime, baselines, integrations
  3. /usr/bin/python3 "$TARGET/adapters/configure_existing.py" --authorized-live-settings   # import OpenCode credentials
  4. cd <project> && safecode                 # or safekimi
Run the test suite from $TARGET: /usr/bin/python3 -m unittest discover -s tests
EOF
