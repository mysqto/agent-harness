#!/usr/bin/env bash
# Sets up a harness deployment: builds the binaries, installs an adapter, writes a config.
#
# Idempotent — safe to re-run. It reports what it changed rather than what it intended to.
set -euo pipefail

ADAPTER=""
PREFIX="${HARNESS_PREFIX:-$HOME/.local}"
RUNTIME="${HARNESS_RUNTIME:-$HOME/.local/state/harness}"
MEMORY_URL="${HARNESS_MEMORY_URL:-http://127.0.0.1:8080}"

usage() {
  cat <<'USAGE'
usage: setup/install.sh [--adapter NAME] [--prefix DIR] [--memory-url URL]

  --adapter NAME     adapter to install from adapters/ (cli, webhook)
  --prefix DIR       where binaries go            (default ~/.local)
  --memory-url URL   memory service base URL      (default http://127.0.0.1:8080)

With no --adapter, builds and configures without installing one.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --adapter)    ADAPTER="$2"; shift 2 ;;
    --prefix)     PREFIX="$2"; shift 2 ;;
    --memory-url) MEMORY_URL="$2"; shift 2 ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

command -v cargo >/dev/null || { echo "cargo not found — install Rust first" >&2; exit 1; }

echo "→ building"
cargo build --release --workspace

mkdir -p "$PREFIX/bin" "$RUNTIME"
install -m 0755 target/release/harness-cli "$PREFIX/bin/harness"
echo "→ installed $PREFIX/bin/harness"

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

Add $PREFIX/bin to PATH if it is not already there.
NEXT
