#!/bin/sh
# Install agent-guard from this checkout into the operator's account.
#
# Layout after installation:
#   $AGENT_GUARD_ROOT (default ~/.local/share/agent-guard)   code, pinned Node runtime, config.json, state/
#   ~/.local/bin/{agent-guard,safecode,opencode-safe,safekimi,token-usage}   thin wrappers
#
# The checkout is the source of truth; the installed copy additionally holds `state/`
# (isolated homes, imported credentials, review baselines). This script never touches
# `state/` and never overwrites an existing `config.json`.
set -eu

REPO="$(cd "$(dirname "$0")" && pwd)"
TARGET="${AGENT_GUARD_ROOT:-$HOME/.local/share/agent-guard}"
BIN="${AGENT_GUARD_BIN:-$HOME/.local/bin}"

if [ "$(uname -s)" != "Darwin" ]; then
  echo "agent-guard requires macOS Seatbelt (sandbox-exec); no other platform is supported." >&2
  exit 1
fi

umask 077
mkdir -p "$TARGET" "$BIN" "$TARGET/runtime" "$TARGET/native" "$TARGET/tests" "$TARGET/vendor" "$TARGET/adapters"
chmod 700 "$TARGET"

# 1. Code. Only reviewed source files; state/ and config.json are left alone.
for file in "$REPO"/*.py "$REPO"/*.mjs "$REPO"/*.cjs "$REPO"/*.swift; do
  cp "$file" "$TARGET/"
done
cp "$REPO"/tests/*.py "$TARGET/tests/"
cp "$REPO"/adapters/*.py "$TARGET/adapters/"
cp "$REPO"/native/SafeIcon.icns "$TARGET/native/"
cp "$REPO"/runtime/package.json "$REPO"/runtime/package-lock.json "$TARGET/runtime/"
rsync -a --exclude __pycache__ "$REPO/vendor/" "$TARGET/vendor/"
chmod 700 "$TARGET/agent_guard.py"

# 2. Node for the supervisor (sandbox_runner.mjs). Pin it in config.json so that a later
#    `nvm install` cannot silently change which binary runs the trusted supervisor.
if [ ! -f "$TARGET/config.json" ]; then
  NODE_BIN="${AGENT_GUARD_NODE:-$(command -v node || true)}"
  if [ -z "$NODE_BIN" ]; then
    echo "No node binary found; install Node 22+ or set AGENT_GUARD_NODE." >&2
    exit 1
  fi
  NODE_BIN="$(cd "$(dirname "$NODE_BIN")" && pwd)/$(basename "$NODE_BIN")"
  printf '{\n  "node": "%s"\n}\n' "$NODE_BIN" > "$TARGET/config.json"
  chmod 600 "$TARGET/config.json"
fi
NODE_BIN="$(/usr/bin/python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node"])' "$TARGET/config.json")"

# 3. Pinned sandbox runtime (@anthropic-ai/sandbox-runtime + undici) from the lock file.
( cd "$TARGET/runtime" && PATH="$(dirname "$NODE_BIN"):$PATH" npm ci --ignore-scripts --no-audit --no-fund --loglevel=error )

# 4. Native Zcode Safe launcher (optional; only needed for the Zcode desktop integration).
if command -v swiftc >/dev/null 2>&1; then
  ( cd "$TARGET" && swiftc -O -framework AppKit ZcodeSafe.swift -o native/ZcodeSafeLauncher 2>/dev/null \
      && codesign -s - -i local.agentguard.zcode.safe-launcher -f native/ZcodeSafeLauncher >/dev/null 2>&1 \
      && chmod 700 native/ZcodeSafeLauncher ) || echo "note: ZcodeSafe launcher was not built (swiftc failed); Zcode Safe.app is unavailable." >&2
fi

# 5. Wrappers. `-I` keeps the supervisor free of PYTHONPATH/site customisation.
write_wrapper() {
  printf '#!/bin/sh\nexec /usr/bin/python3 -I %s %s "$@"\n' "$TARGET/agent_guard.py" "$2" > "$BIN/$1"
  chmod 700 "$BIN/$1"
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
  1. agent-guard doctor                       # verify runtime, baselines, integrations
  2. python3 adapters/configure_existing.py --authorized-live-settings   # import OpenCode credentials (allowlisted providers only)
  3. cd <project> && safecode                 # or safekimi
Run the test suite from $TARGET: /usr/bin/python3 -m unittest discover -s tests
EOF
