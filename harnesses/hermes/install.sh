#!/usr/bin/env bash
# Wires the tool policy into a hermes config: the pre_tool_call hook (layer 2), generated from
# spec/tool-policy.json. There is no layer 1 to write — see README.md.
#
# Idempotent, and it never overwrites a config it did not write: that file holds credentials, so an
# existing one gets the generated fragment beside it and a printed merge instead.
set -euo pipefail

TARGET="${HERMES_HOME:-$HOME/.hermes}"
CONFIG="cli-config.yaml"
GUARD="${HARNESS_GUARD:-harness-guard}"
POLICY="${HARNESS_TOOL_POLICY:-}"

usage() {
  cat <<'USAGE'
usage: harnesses/hermes/install.sh [--target DIR] [--config NAME]
                                   [--guard PATH] [--policy FILE]

  --target DIR    the runtime's home, which must already exist
                  (default $HERMES_HOME, else ~/.hermes)
  --config NAME   config file in that directory      (default cli-config.yaml)
  --guard PATH    the guard executable to wire       (default harness-guard on PATH)
  --policy FILE   policy the hook should enforce     (default: built into the guard)

The config is user-scoped, so there is no --scope: this runtime reads one config file per home
rather than one per project.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --target)  TARGET="$2"; shift 2 ;;
    --config)  CONFIG="$2"; shift 2 ;;
    --guard)   GUARD="$2"; shift 2 ;;
    --policy)  POLICY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)         echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v "$GUARD" >/dev/null 2>&1 || [ -x "$GUARD" ] || {
  echo "guard not found: $GUARD — run setup/install.sh first, or pass --guard" >&2
  exit 1
}

# Deliberately not mkdir -p, unlike the other harness here. This directory is the runtime's home, so
# creating it would put a hook fragment somewhere nothing reads and report success — an adapter that
# looks installed and enforces nothing. If the runtime is not installed, say so.
[ -d "$TARGET" ] || {
  echo "no such directory: $TARGET — install the runtime first, or pass --target" >&2
  exit 1
}

# The hook command the config will carry. Naming the policy explicitly means an operator editing that
# file changes what is enforced; without it the guard falls back to its built-in copy.
hook="$GUARD check --harness hermes"
emit=("$GUARD" emit --harness hermes)
if [ -n "$POLICY" ]; then
  hook="$hook --policy $POLICY"
  emit+=(--policy "$POLICY")
fi
emit+=(--guard "$hook")

config="$TARGET/$CONFIG"
generated="$("${emit[@]}")"

if [ -f "$config" ]; then
  aside="$TARGET/${CONFIG%.*}.harness-policy.yaml"
  printf '%s\n' "$generated" > "$aside"
  echo "→ kept existing $config"
  echo "→ wrote $aside"
  cat <<MERGE

$config already exists, so it was left alone — it holds credentials. Merge the generated fragment
in — with yq:

  yq eval-all 'select(fi==0) * select(fi==1)' "$config" "$aside" > "$config.merged" \\
    && mv "$config.merged" "$config"

Check the result has one hooks.pre_tool_call entry whose command runs the guard.
MERGE
else
  printf '%s\n' "$generated" > "$config"
  echo "→ wrote $config"
fi

cat <<NEXT

Two things to check, because either one leaves the hook silently doing nothing:

1. The refusal reaches the runtime. It reads the verdict from stdout, not from the exit code:

     echo '{"hook_event_name":"pre_tool_call","tool_name":"terminal",
            "tool_input":{"command":"cat ~/.ssh/id_rsa"},"session_id":"s","cwd":".","extra":{}}' \\
       | $hook; echo "exit \$?"

   Expect exit 2 and {"decision":"block","reason":"..."} on stdout. Exit 2 with nothing on stdout is
   read as no opinion.

2. The hook is registered. This runtime asks for consent the first time it sees a hook command, and a
   non-interactive run that has not been given it skips registration with a log warning and nothing
   else. Approve it once at a prompt, or set HERMES_ACCEPT_HOOKS=1 for the run that registers it,
   then confirm with the runtime's own hooks listing.
NEXT
