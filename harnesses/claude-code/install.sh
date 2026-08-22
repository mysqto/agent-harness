#!/usr/bin/env bash
# Wires the tool policy into a Claude Code settings file: deny rules (layer 1) and the PreToolUse
# hook (layer 2), both generated from policy/tool-policy.json.
#
# Idempotent, and it never overwrites a settings file it did not write: an existing one gets the
# generated config beside it and a printed merge instead.
set -euo pipefail

SCOPE="project"
TARGET=""
GUARD="${HARNESS_GUARD:-harness-guard}"
POLICY="${HARNESS_TOOL_POLICY:-}"

usage() {
  cat <<'USAGE'
usage: harnesses/claude-code/install.sh [--scope project|user] [--target DIR]
                                        [--guard PATH] [--policy FILE]

  --scope SCOPE   project → $HARNESS_PROJECT_DIR/.claude or ./.claude, user → ~/.claude
                  (default project)
  --target DIR    write into DIR instead of a scope
  --guard PATH    the guard executable to wire            (default harness-guard on PATH)
  --policy FILE   policy the hook should enforce          (default: built into the guard)
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --scope)   SCOPE="$2"; shift 2 ;;
    --target)  TARGET="$2"; shift 2 ;;
    --guard)   GUARD="$2"; shift 2 ;;
    --policy)  POLICY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)         echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$TARGET" ]; then
  case "$SCOPE" in
    project) TARGET="${HARNESS_PROJECT_DIR:-$PWD}/.claude" ;;
    user)    TARGET="$HOME/.claude" ;;
    *)       echo "unknown scope: $SCOPE (project or user)" >&2; exit 2 ;;
  esac
fi

command -v "$GUARD" >/dev/null 2>&1 || [ -x "$GUARD" ] || {
  echo "guard not found: $GUARD — run setup/install.sh first, or pass --guard" >&2
  exit 1
}

# The hook command the settings file will carry. Naming the policy explicitly means an operator
# editing that file changes what is enforced; without it the guard falls back to its built-in copy.
hook="$GUARD check --harness claude-code"
emit=("$GUARD" emit --harness claude-code)
if [ -n "$POLICY" ]; then
  hook="$hook --policy $POLICY"
  emit+=(--policy "$POLICY")
fi
emit+=(--guard "$hook")

mkdir -p "$TARGET"
settings="$TARGET/settings.json"
generated="$("${emit[@]}")"

if [ -f "$settings" ]; then
  aside="$TARGET/settings.harness-policy.json"
  printf '%s\n' "$generated" > "$aside"
  echo "→ kept existing $settings"
  echo "→ wrote $aside"
  cat <<MERGE

$settings already exists, so it was left alone. Merge the generated config in — with jq:

  jq -s '.[0] * .[1]' "$settings" "$aside" > "$settings.merged" && mv "$settings.merged" "$settings"

Check the result has both a permissions.deny list and a hooks.PreToolUse entry.
MERGE
else
  printf '%s\n' "$generated" > "$settings"
  echo "→ wrote $settings"
fi

cat <<NEXT

Verify the guard refuses something, with no model involved:

  echo '{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}' | $hook; echo "exit \$?"

Expect exit 2 and a refusal naming the private-keys rule.
NEXT
