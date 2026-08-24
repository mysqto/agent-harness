#!/usr/bin/env bash
# Sets up a harness deployment: builds the binaries, installs an adapter, writes a config.
#
# Idempotent — safe to re-run. It reports what it changed rather than what it intended to.
set -euo pipefail

ADAPTER=""
HARNESS=""
PREFIX="${HARNESS_PREFIX:-$HOME/.local}"
RUNTIME="${HARNESS_RUNTIME:-$HOME/.local/state/harness}"
MEMORY_URL="${HARNESS_MEMORY_URL:-http://127.0.0.1:8080}"

usage() {
  cat <<'USAGE'
usage: setup/install.sh [--adapter NAME] [--harness NAME] [--prefix DIR] [--memory-url URL]

  --adapter NAME     adapter to install from adapters/ (cli, webhook)
  --harness NAME     harness to wire the tool policy into, from harnesses/ (claude-code, hermes, openclaw)
  --prefix DIR       where binaries go            (default ~/.local)
  --memory-url URL   memory service base URL      (default http://127.0.0.1:8080)

With no --adapter, builds and configures without installing one. The tool policy and its guard are
installed either way — they are the blocking security layers, not an option.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --adapter)    ADAPTER="$2"; shift 2 ;;
    --harness)    HARNESS="$2"; shift 2 ;;
    --prefix)     PREFIX="$2"; shift 2 ;;
    --memory-url) MEMORY_URL="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# Where the operator ran this from: harness glue writes project-scoped config, and that means their
# project, not this repository.
invoked_from="$PWD"
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

command -v cargo >/dev/null || { echo "cargo not found — install Rust first" >&2; exit 1; }

echo "→ building"
cargo build --release --workspace

mkdir -p "$PREFIX/bin" "$RUNTIME"
install -m 0755 target/release/harness-cli "$PREFIX/bin/harness"
echo "→ installed $PREFIX/bin/harness"
install -m 0755 target/release/harness-guard "$PREFIX/bin/harness-guard"
echo "→ installed $PREFIX/bin/harness-guard"

# The policy is installed as an editable copy, and the guard is pointed at it. Left to its built-in
# copy the guard would ignore local edits, which is the kind of surprise a security control cannot
# afford.
policy="$RUNTIME/tool-policy.json"
if [ -f "$policy" ]; then
  echo "→ keeping existing $policy"
else
  install -m 0644 spec/tool-policy.json "$policy"
  echo "→ installed $policy"
fi

if [ -n "$HARNESS" ]; then
  glue="harnesses/$HARNESS/install.sh"
  [ -x "$glue" ] || { echo "no such harness: $HARNESS (see harnesses/)" >&2; exit 1; }
  # Harness glue stays in its own script: what it writes, and where, is that harness's business.
  # Where its config goes is the harness's business, so it gets the project directory, not a path.
  HARNESS_PROJECT_DIR="$invoked_from" "$glue" --guard "$PREFIX/bin/harness-guard" --policy "$policy"
fi

if [ -n "$ADAPTER" ]; then
  src="adapters/$ADAPTER"
  [ -d "$src" ] || { echo "no such adapter: $ADAPTER (see adapters/)" >&2; exit 1; }
  # Adapters stay in their own language and their own process; installing one is a copy.
  found=0
  for f in "$src"/adapter.*; do
    [ -e "$f" ] || continue
    install -m 0755 "$f" "$PREFIX/bin/harness-adapter-$ADAPTER"
    echo "→ installed $PREFIX/bin/harness-adapter-$ADAPTER"
    found=1
  done
  [ "$found" -eq 1 ] || { echo "adapter $ADAPTER has no adapter.* entry point" >&2; exit 1; }
fi

config="$RUNTIME/config.toml"
if [ -f "$config" ]; then
  echo "→ keeping existing $config"
else
  cat > "$config" <<CONF
# Written by setup/install.sh. Safe to edit; re-running the installer will not overwrite it.
ingress_socket = "$RUNTIME/ingress.sock"
# The egress screen enforces the pattern set this build ships with. Point this at your own copy to
# replace that set; the harness refuses to start if the file named here cannot be read.
# egress_policy = "$RUNTIME/egress-screen.toml"

[memory]
base_url = "$MEMORY_URL"
# Prefer a sidecar when present: it holds the signing key, so this process needs none.
# sidecar_socket = "$RUNTIME/memory-agent.sock"
agent = "harness"
CONF
  echo "→ wrote $config"
fi

cat <<NEXT

Done. To check it over:

  $PREFIX/bin/harness --help
  echo 'hello' | $PREFIX/bin/harness-adapter-${ADAPTER:-cli}   # prints the envelope it would send

Check the guard refuses something, with no model in the loop:

  echo '{"tool":"read","intents":[{"kind":"read","value":"~/.ssh/id_rsa"}]}' \
    | $PREFIX/bin/harness-guard check --policy $policy; echo "exit \$?"   # expect exit 2

Add $PREFIX/bin to PATH if it is not already there.
NEXT
