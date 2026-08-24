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
  --guard "$guard" --policy "$PWD/spec/tool-policy.json" >/dev/null
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
  --guard "$guard" --policy "$PWD/spec/tool-policy.json" >/dev/null
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

echo "→ installing into a scratch runtime home"
home="$work/hermes-home"
mkdir -p "$home"
harnesses/hermes/install.sh --target "$home" \
  --guard "$guard" --policy "$PWD/spec/tool-policy.json" >/dev/null
fragment="$home/cli-config.yaml"
[ -f "$fragment" ] || fail "no config was written"

python3 - "$fragment" <<'YAMLCHECK' || status=1
import sys

text = open(sys.argv[1]).read()
try:
    import yaml

    config = yaml.safe_load(text)
except ImportError:  # No YAML reader here; check the shape textually instead.
    config = None

problems = []
if config is None:
    if "\nhooks:\n  pre_tool_call:\n    - command: " not in text:
        problems.append("no hooks.pre_tool_call entry")
    if "harness-guard" not in text:
        problems.append("the hook does not invoke the guard")
else:
    entries = config.get("hooks", {}).get("pre_tool_call")
    if not isinstance(entries, list) or len(entries) != 1:
        problems.append(f"expected one pre_tool_call entry, found {entries!r}")
    else:
        entry = entries[0]
        if "harness-guard" not in entry.get("command", ""):
            problems.append("the hook does not invoke the guard")
        if not isinstance(entry.get("timeout"), int):
            problems.append("the hook has no integer timeout")
        # A matcher would narrow the hook to the tools it names, leaving the rest unchecked.
        if "matcher" in entry:
            problems.append("the hook carries a matcher")
for problem in problems:
    print(f"::error::generated config: {problem}")
sys.exit(1 if problems else 0)
YAMLCHECK

echo "→ a second run keeps a config file it did not write"
harnesses/hermes/install.sh --target "$home" \
  --guard "$guard" --policy "$PWD/spec/tool-policy.json" >/dev/null
[ -f "$home/cli-config.harness-policy.yaml" ] || fail "an existing config was overwritten"
grep -q 'pre_tool_call' "$fragment" || fail "the config that was kept is not the generated one"

echo "→ a missing runtime home is an error, not a config written where nothing reads it"
if harnesses/hermes/install.sh --target "$work/absent" --guard "$guard" >/dev/null 2>&1; then
  fail "installing into a nonexistent home reported success"
fi
if [ -e "$work/absent" ]; then fail "installing into a nonexistent home created it"; fi

echo "→ the wired hook says its refusal where that harness reads it"
hermes_hook="$(sed -n 's/^ *- command: "\(.*\)"$/\1/p' "$fragment")"
[ -n "$hermes_hook" ] || fail "no hook command could be read back out of the config"

# That runtime parses the verdict out of stdout and reads empty stdout as no opinion, so the exit
# code alone proves nothing here — the block has to be *said*.
blocked() {
  python3 -c 'import json,sys
d = json.load(sys.stdin)
sys.exit(0 if d.get("decision") == "block" and d.get("reason") else 1)'
}
verdict() {
  local payload="$1" expected="$2" said code
  set +e
  said="$(printf '%s' "$payload" | $hermes_hook 2>/dev/null)"
  code=$?
  set -e
  [ "$code" = "$expected" ] || fail "expected exit $expected, got $code, for $payload"
  if [ "$expected" = 2 ]; then
    if printf '%s' "$said" | blocked; then
      note "exit $code, block on stdout — $payload"
    else
      fail "a block said nothing readable on stdout (${said:-empty}) for $payload"
    fi
  elif [ -n "$said" ]; then
    fail "a permitted call said something on stdout ($said) for $payload"
  else
    note "exit $code, silent — $payload"
  fi
}
envelope() {
  printf '{"hook_event_name":"pre_tool_call","tool_name":"%s","tool_input":%s,' "$1" "$2"
  printf '"session_id":"s","cwd":".","extra":{}}'
}
verdict "$(envelope terminal '{"command":"cat ~/.ssh/id_rsa"}')" 2
verdict "$(envelope terminal '{"command":"ls && sudo rm -rf ~"}')" 2
verdict "$(envelope web_extract '{"url":"https://unlisted.test/x"}')" 2
verdict "$(envelope read_file '{"path":"README.md"}')" 0
# The wrong harness, a renamed field, arguments that were not a mapping: blocks that would otherwise
# arrive only as an exit code this runtime does not read.
verdict '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' 2

if [ "$status" -eq 0 ]; then
  echo "glue: clean — installers parse, wire a hook, and the hook refuses"
fi
exit "$status"
