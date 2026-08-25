#!/usr/bin/env bash
# Wires the tool policy into an OpenClaw deployment: the exec gate (layer 1) and a `before_tool_call`
# plugin that spawns the guard (layer 2), both generated from spec/tool-policy.json.
#
# Idempotent, and it never writes the harness's config file. That file is one large JSON5 document
# holding credentials, so this prints the fragment to merge and the validated command that merges it.
# `--apply` runs that command; without it nothing outside the plugin directory is touched.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

GUARD="${HARNESS_GUARD:-harness-guard}"
POLICY="${HARNESS_TOOL_POLICY:-}"
OPENCLAW="${HARNESS_OPENCLAW:-openclaw}"
CONFIG=""
PLUGIN_DIR="${HARNESS_OPENCLAW_PLUGIN_DIR:-$HOME/.local/share/harness/openclaw-plugin}"
AGENT="main"
APPLY=0
BACKEND_ARGS=()

usage() {
  cat <<'USAGE'
usage: harnesses/openclaw/install.sh [--config FILE] [--plugin-dir DIR] [--agent NAME]
                                     [--guard PATH] [--policy FILE] [--openclaw CMD]
                                     [--backend-arg WORD]... [--apply]

  --config FILE     the harness config to merge into. Default follows the documented order:
                    $OPENCLAW_CONFIG_PATH, $OPENCLAW_STATE_DIR/openclaw.json, ~/.openclaw/openclaw.json
  --plugin-dir DIR  where the guard plugin is installed  (default ~/.local/share/harness/openclaw-plugin)
  --agent NAME      agent the exec allowlist entries are added for      (default main)
  --guard PATH      the guard executable to wire          (default harness-guard on PATH)
  --policy FILE     policy the plugin should enforce      (default: built into the guard)
  --openclaw CMD    the harness CLI, used to apply        (default openclaw on PATH)
  --backend-arg W   one argv word to pin on the Claude CLI backend, repeatable. Without an
                    --allowedTools among them no exec gate is generated at all: the gate on its own
                    refuses every native tool call, which leaves an agent that answers and never
                    writes. Pass the flag and the commands the agents need, one word per flag
  --apply           merge the fragment with `openclaw config patch`. Without this, nothing outside
                    the plugin directory is written and the commands are printed instead.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --config)     CONFIG="$2"; shift 2 ;;
    --plugin-dir) PLUGIN_DIR="$2"; shift 2 ;;
    --agent)      AGENT="$2"; shift 2 ;;
    --guard)      GUARD="$2"; shift 2 ;;
    --policy)     POLICY="$2"; shift 2 ;;
    --openclaw)   OPENCLAW="$2"; shift 2 ;;
    --backend-arg) BACKEND_ARGS+=("$2"); shift 2 ;;
    --apply)      APPLY=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v "$GUARD" >/dev/null 2>&1 || [ -x "$GUARD" ] || {
  echo "guard not found: $GUARD — run setup/install.sh first, or pass --guard" >&2
  exit 1
}

# The documented resolution order. Replicated rather than asked of the CLI because this has to give
# the same answer when the CLI is not installed, and because the answer decides whether we refuse.
if [ -z "$CONFIG" ]; then
  if [ -n "${OPENCLAW_CONFIG_PATH:-}" ]; then
    CONFIG="$OPENCLAW_CONFIG_PATH"
  elif [ -n "${OPENCLAW_STATE_DIR:-}" ]; then
    CONFIG="$OPENCLAW_STATE_DIR/openclaw.json"
  else
    CONFIG="$HOME/.openclaw/openclaw.json"
  fi
fi

# No config means no deployment to wire. Writing one from here would produce a file the harness has
# never validated, so this stops instead.
[ -f "$CONFIG" ] || {
  echo "no harness config at $CONFIG — set it up first, or pass --config" >&2
  exit 1
}

# A plugin directory holding some other plugin is not ours to overwrite.
manifest="$PLUGIN_DIR/openclaw.plugin.json"
plugin_id="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$here/plugin/openclaw.plugin.json" | head -1)"
if [ -f "$manifest" ]; then
  found="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -1)"
  [ "$found" = "$plugin_id" ] || {
    echo "$PLUGIN_DIR already holds the plugin '$found' — pass a different --plugin-dir" >&2
    exit 1
  }
fi

mkdir -p "$PLUGIN_DIR"
for file in openclaw.plugin.json package.json index.mjs; do
  install -m 0644 "$here/plugin/$file" "$PLUGIN_DIR/$file"
done
echo "→ installed the guard plugin in $PLUGIN_DIR"

# The plugin spawns this argv, so the policy is named explicitly: without it the guard falls back to
# its built-in copy and an operator editing the installed policy changes nothing.
hook="$GUARD check --harness openclaw"
emit=("$GUARD" emit --harness openclaw)
if [ -n "$POLICY" ]; then
  hook="$hook --policy $POLICY"
  emit+=(--policy "$POLICY")
fi
emit+=(--guard "$hook")
# One flag per word, never one flag holding a line: a tool pattern like `Bash(git status:*)` carries
# a space, and a shell re-split of it would pre-approve two halves that are neither of them a
# command — a pinning that reads right and pre-approves nothing.
for word in ${BACKEND_ARGS[@]+"${BACKEND_ARGS[@]}"}; do
  emit+=(--backend-arg "$word")
done

fragment="$PLUGIN_DIR/config-fragment.json"
# `${plugin_dir}` is the generator's placeholder: it cannot know where this run installed the plugin,
# and a guessed path would be a load path pointing at nothing, which loads silently and enforces
# nothing.
"${emit[@]}" | sed "s|\${plugin_dir}|$PLUGIN_DIR|g" > "$fragment"
echo "→ wrote $fragment"

if [ "$APPLY" -eq 1 ]; then
  command -v "$OPENCLAW" >/dev/null 2>&1 || [ -x "$OPENCLAW" ] || {
    echo "harness CLI not found: $OPENCLAW — needed for --apply, or merge by hand" >&2
    exit 1
  }
  # A patch replaces an array rather than extending it, so an existing load path would be dropped.
  # Refused rather than merged blind: dropping a load path silently unloads someone else's plugin.
  existing="$("$OPENCLAW" config get plugins.load.paths 2>/dev/null || true)"
  case "$existing" in
    ''|'[]'|'null'|*"$PLUGIN_DIR"*) ;;
    *)
      echo "plugins.load.paths already holds entries a patch would replace:" >&2
      echo "  $existing" >&2
      echo "add \"$PLUGIN_DIR\" to that array by hand, then re-run without --apply" >&2
      exit 1
      ;;
  esac
  "$OPENCLAW" config patch --file "$fragment" --dry-run
  "$OPENCLAW" config patch --file "$fragment"
  echo "→ merged $fragment into $CONFIG"
else
  cat <<MERGE

$CONFIG was left alone. Merge the fragment with one validated write:

  $OPENCLAW config patch --file "$fragment" --dry-run   # schema-checks it, writes nothing
  $OPENCLAW config patch --file "$fragment"

A patch replaces arrays rather than extending them. Check plugins.load.paths first, and add the
directory to what is already there instead if that list is not empty:

  $OPENCLAW config get plugins.load.paths
MERGE
fi

cat <<NEXT

Two more steps, because neither is the policy's to decide.

Name the commands that may run unattended — at minimum the memory writer, or agents cannot record
anything:

  $OPENCLAW approvals allowlist add --agent $AGENT "\$HOME/.local/bin/yaam-emit"

And point that writer at the memory sidecar, so a command line never has to carry the socket:

  $OPENCLAW config set env.vars.YAAM_SOCKET "\$HOME/.local/state/harness/sockets/$AGENT.sock"
  $OPENCLAW config set env.vars.YAAM_AGENT "$AGENT"

Then check the guard refuses something, with no model in the loop:

  echo '{"toolName":"exec","params":{"command":"cat ~/.ssh/id_rsa"}}' | $hook; echo "exit \$?"

Expect exit 2 and a refusal naming the private-keys rule. Restart the gateway to load the plugin.
NEXT
