#!/usr/bin/env bash
# Tests the shell that installs the tool policy. The guard's own rules are covered by cargo tests;
# this covers the part cargo cannot see — that the installers parse, write what the harness reads,
# and wire a hook that actually refuses something.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
note() { echo "  $*"; }
fail() { echo "::error::$*"; status=1; }

echo "→ shell parses"
while IFS= read -r script; do
  bash -n "$script" || fail "$script does not parse"
done < <(find setup adapters harnesses -name '*.sh' -type f | sort)

echo "→ every harness has an executable installer"
for dir in harnesses/*/; do
  [ -d "$dir" ] || continue
  [ -x "$dir/install.sh" ] || fail "$dir has no executable install.sh"
done

echo "→ building the guard"
cargo build --quiet -p harness-policy --bin harness-guard
guard="$PWD/target/debug/harness-guard"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "→ installing into a scratch project"
HARNESS_PROJECT_DIR="$work" harnesses/claude-code/install.sh \
  --guard "$guard" --policy "$PWD/policy/tool-policy.json" >/dev/null
settings="$work/.claude/settings.json"
[ -f "$settings" ] || fail "no settings file was written"

python3 - "$settings" <<'PY' || status=1
import json, sys
settings = json.load(open(sys.argv[1]))
hooks = settings.get("hooks", {}).get("PreToolUse", [])
deny = settings.get("permissions", {}).get("deny", [])
problems = []
if len(hooks) != 1:
    problems.append(f"expected one PreToolUse entry, found {len(hooks)}")
else:
    commands = [hook.get("command", "") for hook in hooks[0].get("hooks", [])]
    if not any("harness-guard" in command for command in commands):
        problems.append("the hook does not invoke the guard")
if not any(entry.startswith("Read(") for entry in deny):
    problems.append("no read denies were generated")
if not any(entry.startswith("Bash(") for entry in deny):
    problems.append("no command denies were generated")
for problem in problems:
    print(f"::error::generated settings: {problem}")
sys.exit(1 if problems else 0)
PY

echo "→ a second run keeps a settings file it did not write"
HARNESS_PROJECT_DIR="$work" harnesses/claude-code/install.sh \
  --guard "$guard" --policy "$PWD/policy/tool-policy.json" >/dev/null
[ -f "$work/.claude/settings.harness-policy.json" ] || fail "an existing settings file was overwritten"

echo "→ the wired hook refuses and permits"
hook="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hooks"]["PreToolUse"][0]["hooks"][0]["command"])' "$settings")"
check() {
  local payload="$1" expected="$2"
  set +e
  printf '%s' "$payload" | $hook >/dev/null 2>&1
  local code=$?
  set -e
  if [ "$code" != "$expected" ]; then
    fail "expected exit $expected, got $code, for $payload"
  else
    note "exit $code — $payload"
  fi
}
check '{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}' 2
check '{"tool_name":"Bash","tool_input":{"command":"ls && sudo rm -rf ~"}}' 2
check '{"tool_name":"WebFetch","tool_input":{"url":"https://unlisted.test/x"}}' 2
check '{"tool_name":"Read","tool_input":{"file_path":"README.md"}}' 0

if [ "$status" -eq 0 ]; then
  echo "glue: clean — installers parse, wire a hook, and the hook refuses"
fi
exit "$status"
