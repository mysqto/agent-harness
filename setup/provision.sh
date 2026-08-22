#!/usr/bin/env bash
# Provisions the confinement layer: per-agent workspaces, signing keys, and the sandbox artefacts.
#
# Separate from install.sh on purpose. Installing binaries is something a developer does on a
# laptop; this touches key material and permissions, so it is a deliberate second step an operator
# runs where the deployment lives.
#
# Idempotent — safe to re-run. It reports what it changed rather than what it intended to, and it
# never replaces a key an agent is already signing with (see rotate below for that).
set -euo pipefail

ROOT="${HARNESS_ROOT:-$HOME/.local/state/harness}"
AGENTS=()
POLICY=""
ALLOW=()
UNIT_DIR=""
ACTION="provision"

usage() {
  cat <<'USAGE'
usage: setup/provision.sh --agent NAME [--agent NAME ...] [options]
       setup/provision.sh --audit
       setup/provision.sh --rotate NAME

  --agent NAME       agent to provision. Repeatable; one signing key per agent.
  --root DIR         deployment root          (default ~/.local/state/harness)
  --policy FILE      declared policy as JSON  (default: the Phase 0 policy)
  --allow CIDR       egress destination to allow. Repeatable; unlisted is denied.
  --install-unit DIR copy the generated unit into DIR (e.g. ~/.config/systemd/user)
  --audit            report anything whose permissions are wider than the policy
  --rotate NAME      rotate one agent's key, keeping the old one valid for 24h

The sandbox artefacts are generated from one policy: a systemd unit for a host and a container
profile for a lab, so what the lab exercises is what production runs. The script refuses to write
them unless both are read back and agree.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --agent)        AGENTS+=("$2"); shift 2 ;;
    --root)         ROOT="$2"; shift 2 ;;
    --policy)       POLICY="$2"; shift 2 ;;
    --allow)        ALLOW+=("$2"); shift 2 ;;
    --install-unit) UNIT_DIR="$2"; shift 2 ;;
    --audit)        ACTION="audit"; shift ;;
    --rotate)       ACTION="rotate"; ROTATE="$2"; shift 2 ;;
    -h|--help)      usage; exit 0 ;;
    *)              echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"

command -v cargo >/dev/null || { echo "cargo not found — install Rust first" >&2; exit 1; }

echo "→ building harness-sandbox"
cargo build --release -p harness-sandbox
bin="$repo/target/release/harness-sandbox"

case "$ACTION" in
  audit)
    exec "$bin" --root "$ROOT" audit
    ;;
  rotate)
    # Overlapping validity: the retired key stays acceptable for 24h, so requests already in
    # flight or spooled under it do not fail at the moment somebody is rotating.
    "$bin" --root "$ROOT" rotate --agent "$ROTATE"
    echo
    echo "Distribute the new key, then confirm nothing still signs with the old one before the"
    echo "window closes. Runbook: knowledge/runbooks/memory-key-rotation.md"
    exit 0
    ;;
esac

[ "${#AGENTS[@]}" -gt 0 ] || { echo "at least one --agent is required" >&2; usage >&2; exit 2; }

args=(--root "$ROOT" provision)
for agent in "${AGENTS[@]}"; do args+=(--agent "$agent"); done
[ -n "$POLICY" ] && args+=(--policy "$POLICY")
for cidr in ${ALLOW[@]+"${ALLOW[@]}"}; do args+=(--allow "$cidr"); done

"$bin" "${args[@]}"

unit="$ROOT/sandbox/harness.service"
if [ -n "$UNIT_DIR" ]; then
  mkdir -p "$UNIT_DIR"
  install -m 0644 "$unit" "$UNIT_DIR/harness.service"
  echo "→ installed $UNIT_DIR/harness.service"
fi

cat <<NEXT

Done. To check it over:

  $bin --root $ROOT audit    # permissions still at least as tight as the policy
  $bin --root $ROOT check    # the unit and the container profile still agree

The container profile at $ROOT/sandbox/harness.container.json carries the same policy as the unit,
with the runtime flags in runtime_args. A lab launcher passes those flags, so it exercises the
sandbox the host runs rather than one of its own.

One step this script deliberately does not take: ownership. Creating a directory owned by another
user needs privileges this script should not hold, so it sets modes and leaves owners to you. On a
multi-user host, as root:

  chown -R memsvc:operators $ROOT/memory      # agent users are NOT in the operators group
  chown -R AGENT:AGENT      $ROOT/agents/AGENT $ROOT/memory/private/AGENT

Until that is done, the modes are enforced against a single account, which confines nothing on a
host where the agents run as their own users.
NEXT
