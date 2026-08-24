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
## OpenClaw ###################################################################
# This harness reaches the tool-call boundary through a plugin rather than a hook command, and its
# config is one large file holding credentials. So what is tested here is different: that the
# installer refuses to touch that file, that the fragment it prints is real, and that the plugin
# fails closed.

oc="harnesses/openclaw/install.sh"
ocwork="$work/openclaw"
mkdir -p "$ocwork/state" "$ocwork/plug"
config="$ocwork/state/openclaw.json"
printf '{"gateway":{"port":19001}}\n' > "$config"

echo "→ the openclaw installer refuses a target that is not there"
set +e
"$oc" --guard "$guard" --config "$ocwork/state/absent.json" --plugin-dir "$ocwork/plug" \
  >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the installer succeeded with no config to merge into"

echo "→ installing beside a config it must not touch"
before="$(cat "$config")"
"$oc" --guard "$guard" --policy "$PWD/spec/tool-policy.json" \
  --config "$config" --plugin-dir "$ocwork/plug" >/dev/null
fragment="$ocwork/plug/config-fragment.json"
[ -f "$fragment" ] || fail "no config fragment was written"
for file in index.mjs openclaw.plugin.json package.json; do
  [ -f "$ocwork/plug/$file" ] || fail "the plugin is missing $file"
done
[ "$(cat "$config")" = "$before" ] || fail "the installer edited the live config"

echo "→ the fragment is valid JSON and carries what it claims"
python3 - "$fragment" "$ocwork/plug" <<'PY' || status=1
import json, sys
fragment, plugin_dir = sys.argv[1], sys.argv[2]
config = json.load(open(fragment))
problems = []

exec_gate = config.get("tools", {}).get("exec", {})
if exec_gate.get("security") != "allowlist":
    problems.append(f"exec security is {exec_gate.get('security')!r}, not the default-deny posture")
if exec_gate.get("ask") != "on-miss":
    problems.append(f"exec ask is {exec_gate.get('ask')!r}, so a miss would not reach a person")

plugins = config.get("plugins", {})
paths = plugins.get("load", {}).get("paths", [])
if paths != [plugin_dir]:
    problems.append(f"load paths are {paths}, not the directory the plugin was installed to")
if any("${" in path for path in paths):
    problems.append("a placeholder survived into the fragment, so the plugin would never load")

entry = plugins.get("entries", {}).get("harness-tool-policy")
if not entry:
    problems.append("the guard plugin has no entry, so it is installed and not enabled")
else:
    if entry.get("enabled") is not True:
        problems.append("the guard plugin entry is not enabled")
    argv = entry.get("config", {}).get("guard")
    if not isinstance(argv, list) or not argv:
        problems.append(f"the guard is {argv!r}, not an argv the plugin can spawn")
    elif "--harness" not in argv or "openclaw" not in argv:
        problems.append(f"the guard argv does not select this harness: {argv}")
    # This hook has no host-side default timeout, so an unbounded handler wedges the tool call.
    plugin_budget = entry.get("config", {}).get("timeoutMs")
    host_budget = entry.get("hooks", {}).get("timeouts", {}).get("before_tool_call")
    if not isinstance(plugin_budget, int) or not isinstance(host_budget, int):
        problems.append(f"the hook is unbounded: plugin={plugin_budget!r} host={host_budget!r}")
    elif host_budget <= plugin_budget:
        problems.append("the host would time out first, and its refusal names no rule")

# The one thing this harness must NOT claim: its node deny list matches command ids, not shell text.
rendered = json.dumps(config)
if "denyCommands" in rendered:
    problems.append("the fragment claims a command deny list this harness cannot apply")

for problem in problems:
    print(f"::error::generated fragment: {problem}")
sys.exit(1 if problems else 0)
PY

echo "→ the guard the fragment names refuses and permits"
# Read the argv the plugin would spawn, so what is exercised is the fragment's own wiring rather
# than a command line this script composed.
mapfile -t ocargv < <(python3 -c \
  'import json,sys; print(*json.load(open(sys.argv[1]))["plugins"]["entries"]["harness-tool-policy"]["config"]["guard"], sep="\n")' \
  "$fragment")
occheck() {
  local payload="$1" expected="$2" code
  set +e
  printf '%s' "$payload" | "${ocargv[@]}" >/dev/null 2>&1
  code=$?
  set -e
  if [ "$code" != "$expected" ]; then
    fail "openclaw: expected exit $expected, got $code, for $payload"
  else
    note "exit $code — $payload"
  fi
}
occheck '{"toolName":"exec","params":{"command":"cat ~/.ssh/id_rsa"}}' 2
occheck '{"toolName":"exec","params":{"command":"ls && sudo rm -rf ~"}}' 2
occheck '{"toolName":"web_fetch","params":{"url":"https://unlisted.test/x"}}' 2
occheck '{"toolName":"apply_patch","params":{},"derivedPaths":["/etc/crontab"]}' 2
occheck '{"toolName":"read","params":{"path":"README.md"}}' 0
# A program is not a command line. Reading it as one permits what the shell line it builds would not.
occheck '{"toolName":"exec","toolKind":"code_mode_exec","params":{"command":"await sh(\"ls\")"}}' 2

echo "→ a second run changes nothing"
digest="$(cat "$fragment" "$ocwork/plug/index.mjs" | cksum)"
"$oc" --guard "$guard" --policy "$PWD/spec/tool-policy.json" \
  --config "$config" --plugin-dir "$ocwork/plug" >/dev/null
[ "$(cat "$fragment" "$ocwork/plug/index.mjs" | cksum)" = "$digest" ] \
  || fail "a second run rewrote the plugin or the fragment differently"
[ "$(cat "$config")" = "$before" ] || fail "a second run edited the live config"

echo "→ it will not overwrite somebody else's plugin directory"
other="$ocwork/other"
mkdir -p "$other"
printf '{"id":"some-other-plugin"}\n' > "$other/openclaw.plugin.json"
set +e
"$oc" --guard "$guard" --config "$config" --plugin-dir "$other" >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the installer overwrote a directory holding another plugin"
grep -q 'some-other-plugin' "$other/openclaw.plugin.json" \
  || fail "the other plugin's manifest was replaced"

echo "→ --apply refuses to drop load paths a patch would replace"
stub="$ocwork/bin"
mkdir -p "$stub"
cat > "$stub/openclaw" <<'STUB'
#!/usr/bin/env bash
# Enough of the harness CLI to answer the one question the installer asks before it applies.
if [ "$1" = "config" ] && [ "$2" = "get" ]; then
  echo '["/opt/somebody-elses-plugin"]'
  exit 0
fi
echo "stub: refusing to run $*" >&2
exit 1
STUB
chmod +x "$stub/openclaw"
set +e
"$oc" --guard "$guard" --config "$config" --plugin-dir "$ocwork/plug" \
  --openclaw "$stub/openclaw" --apply >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "--apply would have replaced an existing plugins.load.paths"

echo "→ the plugin fails closed"
if command -v node >/dev/null 2>&1; then
  node --input-type=module - "$guard" <<'JS' || status=1
import { consult } from "./harnesses/openclaw/plugin/index.mjs";

const guard = [process.argv[2], "check", "--harness", "openclaw"];
const silent = { warn() {} };
const problems = [];
const blocked = (result) => Boolean(result && result.block);

// A refusal the policy makes, and a call it permits: the plugin must pass both through unchanged.
if (!blocked(await consult(guard, 5000, { toolName: "exec", params: { command: "cat ~/.ssh/id_rsa" } }, silent)))
  problems.push("a denied call was let through");
if (blocked(await consult(guard, 5000, { toolName: "read", params: { path: "README.md" } }, silent)))
  problems.push("a permitted call was blocked");

// Every way the guard can fail to answer has to end in a refusal, not a pass.
if (!blocked(await consult([], 5000, { toolName: "exec", params: { command: "ls" } }, silent)))
  problems.push("an unconfigured guard let a call through");
if (!blocked(await consult(["/nonexistent/guard"], 5000, { toolName: "exec", params: { command: "ls" } }, silent)))
  problems.push("a guard that cannot be started let a call through");
if (!blocked(await consult(["/bin/sleep", "5"], 150, { toolName: "exec", params: { command: "ls" } }, silent)))
  problems.push("a guard that never answered let a call through");

for (const problem of problems) console.log(`::error::openclaw plugin: ${problem}`);
process.exit(problems.length ? 1 : 0);
JS
  [ "$status" -eq 0 ] && note "refuses on deny, on no guard, on no binary and on no answer"
else
  fail "node is not installed, so the plugin's decision path went untested"
fi
## OpenClaw recall #############################################################
# The other half of that harness: a plugin owning the memory slot that recalls before a reply. What
# is tested here is the opposite of what is tested above — this one must fail *open*. A lookup that
# cannot answer has to let the turn through, and it has to stay distinguishable in the log from a
# lookup that legitimately found nothing.

ocmem="harnesses/openclaw/install-memory.sh"
memwork="$work/openclaw-memory"
mkdir -p "$memwork/state" "$memwork/plug" "$memwork/bin"
memconfig="$memwork/state/openclaw.json"
printf '{"gateway":{"port":19002}}\n' > "$memconfig"

# Stand-ins for the read tool, one per answer it can give. Each ignores its arguments except the one
# that records them: what the plugin appends to the configured argv is part of the wiring.
reader() { echo "$memwork/bin/reader-$1"; }
cat > "$(reader records)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" > "$READER_ARGS_FILE"
cat <<'JSON'
{"records":[
 {"record_id":"01AAAA","received_at":"2026-01-01T00:00:00Z","action":"deploy","outcome":"ok",
  "agent":"builder","entities":[{"kind":"service","id":"api"}],"attrs":{"env":"staging"},
  "tags":["release"]},
 {"record_id":"01BBBB","received_at":"2026-01-02T00:00:00Z","action":"review","outcome":"failed",
  "agent":"builder","entities":[{"kind":"pull_request","id":"12"}],"attrs":{},"tags":[]}],
 "degraded":false,"omitted":[],"token_estimate":57}
JSON
STUB
cat > "$(reader empty)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" > "$READER_ARGS_FILE"
printf '{"records":[],"degraded":false,"omitted":[],"token_estimate":0}'
STUB
cat > "$(reader degraded)" <<'STUB'
#!/usr/bin/env bash
cat <<'JSON'
{"records":[{"record_id":"01CCCC","received_at":"2026-01-03T00:00:00Z","action":"deploy",
 "outcome":"ok","agent":"builder","entities":[],"attrs":{},"tags":[]}],
 "degraded":true,"omitted":["entity timeline was not consulted in time"],"token_estimate":22}
JSON
STUB
cat > "$(reader refused)" <<'STUB'
#!/usr/bin/env bash
echo "the service refused this request (400): unknown parameter" >&2
exit 8
STUB
cat > "$(reader garbage)" <<'STUB'
#!/usr/bin/env bash
printf 'not json at all'
STUB
cat > "$(reader slow)" <<'STUB'
#!/usr/bin/env bash
sleep 30
STUB
chmod +x "$memwork"/bin/reader-*

echo "→ the recall installer refuses a read tool that is not there"
set +e
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$memwork/bin/absent" \
  >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the recall installer wired a reader that does not exist"

echo "→ the recall installer refuses a target that is not there"
set +e
"$ocmem" --config "$memwork/state/absent.json" --plugin-dir "$memwork/plug" \
  --reader "$(reader records)" >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the recall installer succeeded with no config to merge into"

echo "→ installing beside a config it must not touch"
membefore="$(cat "$memconfig")"
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --socket "$memwork/state/main.read.sock" --agent main >/dev/null
memfragment="$memwork/plug/config-fragment.json"
[ -f "$memfragment" ] || fail "no recall fragment was written"
for file in index.mjs openclaw.plugin.json package.json; do
  [ -f "$memwork/plug/$file" ] || fail "the recall plugin is missing $file"
done
[ "$(cat "$memconfig")" = "$membefore" ] || fail "the recall installer edited the live config"

echo "→ the fragment names the slot, and names it exclusively"
python3 - "$memfragment" "$memwork/plug" "$(reader records)" <<'PY' || status=1
import json, sys
fragment, plugin_dir, reader = sys.argv[1], sys.argv[2], sys.argv[3]
config = json.load(open(fragment))
problems = []
plugins = config.get("plugins", {})

if plugins.get("slots", {}).get("memory") != "harness-memory":
    problems.append(f"the memory slot is {plugins.get('slots')!r}, so the built-in still fills it")
if plugins.get("load", {}).get("paths") != [plugin_dir]:
    problems.append(f"load paths are {plugins.get('load')!r}, not where the plugin was installed")

entry = plugins.get("entries", {}).get("harness-memory")
if not entry:
    problems.append("the recall plugin has no entry, so it is installed and not enabled")
else:
    if entry.get("enabled") is not True:
        problems.append("the recall plugin entry is not enabled")
    argv = entry.get("config", {}).get("read")
    if not isinstance(argv, list) or not argv:
        problems.append(f"the reader is {argv!r}, not an argv the plugin can spawn")
    else:
        if argv[0] != reader:
            problems.append(f"the reader argv does not name the read tool: {argv}")
        # One read shape is wired, and the plugin refuses any other. A fragment naming a different
        # one would install a plugin that recalls nothing on every turn.
        if "bundle" not in argv:
            problems.append(f"the reader argv names no bundle read: {argv}")
        if "--socket" not in argv:
            problems.append(f"the reader argv names no socket: {argv}")
    budget = entry.get("config", {}).get("timeoutMs")
    host = entry.get("hooks", {}).get("timeouts", {}).get("before_prompt_build")
    if not isinstance(budget, int) or not isinstance(host, int):
        problems.append(f"the lookup is unbounded: plugin={budget!r} host={host!r}")
    elif host <= budget:
        problems.append("the host would time out first, and its message says only that a hook failed")

# Two things owning memory is worse than either. The slot disables the built-in backend; the recall
# sub-agent is a separate plugin and has to be turned off by name.
if plugins.get("entries", {}).get("active-memory", {}).get("enabled") is not False:
    problems.append("the built-in recall sub-agent is left on, so two things inject memory")

for problem in problems:
    print(f"::error::generated fragment: {problem}")
sys.exit(1 if problems else 0)
PY

echo "→ a second run changes nothing"
memdigest="$(cat "$memfragment" "$memwork/plug/index.mjs" | cksum)"
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --socket "$memwork/state/main.read.sock" --agent main >/dev/null
[ "$(cat "$memfragment" "$memwork/plug/index.mjs" | cksum)" = "$memdigest" ] \
  || fail "a second recall install rewrote the plugin or the fragment differently"
[ "$(cat "$memconfig")" = "$membefore" ] || fail "a second recall install edited the live config"

echo "→ it will not overwrite somebody else's plugin directory"
memother="$memwork/other"
mkdir -p "$memother"
printf '{"id":"some-other-plugin"}\n' > "$memother/openclaw.plugin.json"
set +e
"$ocmem" --config "$memconfig" --plugin-dir "$memother" --reader "$(reader records)" >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the recall installer overwrote a directory holding another plugin"
grep -q 'some-other-plugin' "$memother/openclaw.plugin.json" \
  || fail "the other plugin's manifest was replaced"

echo "→ --apply refuses to drop the load path the guard plugin lives on"
set +e
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --openclaw "$stub/openclaw" --apply >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "--apply would have replaced an existing plugins.load.paths"

echo "→ recall fails open, and says which kind of nothing it got"
if command -v node >/dev/null 2>&1; then
  # Written out rather than inlined because it is run several times: once against the plugin, then
  # once against each mutant, to check these assertions can actually fail.
  cat > "$work/recall-assertions.mjs" <<'JS'
// Exercises the recall path without a gateway around it. argv[2] is the module under test, argv[3]
// the directory holding the stand-in readers.
const [, , modulePath, binDir] = process.argv;
const mod = await import(modulePath);
const { recall, renderContext, injectionFrom, report, bounds, actorFor, HEADING } = mod;

const problems = [];
const reader = (name, ...rest) => [`${binDir}/reader-${name}`, "bundle", ...rest];
const recorder = () => {
  const lines = [];
  return { lines, info: (m) => lines.push(["info", String(m)]), warn: (m) => lines.push(["warn", String(m)]) };
};
const said = (log, level) => log.lines.filter(([at]) => at === level).map(([, m]) => m).join("\n");

// A lookup that found something reaches the injection point, as structure and not as prose.
const found = await recall({ read: reader("records") }, "builder");
const injected = injectionFrom(found);
if (found.kind !== "recalled") problems.push(`a bundle with records gave ${found.kind}: ${found.why ?? ""}`);
if (!injected?.prependContext) problems.push("a bundle with records injected nothing");
else {
  const text = injected.prependContext;
  if (!text.startsWith(HEADING)) problems.push("the injected block does not say what it is");
  for (const expected of ["action=deploy", "outcome=ok", "service:api", "env=staging", "action=review"]) {
    if (!text.includes(expected)) problems.push(`the injected block dropped ${expected}`);
  }
}

// An empty match: no context, and a line saying the store was quiet rather than broken.
const emptyLog = recorder();
const empty = await recall({ read: reader("empty") }, "builder");
report(empty, emptyLog);
if (empty.kind !== "empty") problems.push(`an empty bundle gave ${empty.kind}`);
if (injectionFrom(empty) !== undefined) problems.push("an empty bundle injected something");
if (!/matched nothing/.test(said(emptyLog, "info"))) problems.push("an empty match was not reported as one");
if (said(emptyLog, "warn")) problems.push(`an empty match warned: ${said(emptyLog, "warn")}`);

// Every way a lookup can fail to answer: the turn proceeds, and the log says the plumbing failed.
for (const [label, settings] of [
  ["no reader configured", {}],
  ["a reader that is not there", { read: reader("absent") }],
  ["a read shape this does not inject", { read: [`${binDir}/reader-records`, "records"] }],
  ["a refused read", { read: reader("refused") }],
  ["an unreadable answer", { read: reader("garbage") }],
  ["a reader that never answered", { read: reader("slow"), timeoutMs: 200 }],
]) {
  const log = recorder();
  const outcome = await recall(settings, "builder");
  report(outcome, log);
  if (outcome.kind !== "unavailable") problems.push(`${label} gave ${outcome.kind}, not unavailable`);
  if (injectionFrom(outcome) !== undefined) problems.push(`${label} injected context`);
  if (!/recall unavailable/.test(said(log, "warn"))) problems.push(`${label} was not warned about`);
  if (/matched nothing/.test(said(log, "info"))) problems.push(`${label} was reported as an empty match`);
  if (!outcome.why) problems.push(`${label} gave no reason`);
}

// A partial bundle is safe to answer from and unsafe to act on, so it has to say so.
const partial = await recall({ read: reader("degraded") }, "builder");
if (partial.kind !== "recalled" || !partial.degraded) problems.push("a degraded bundle did not report itself");
if (!/partial/i.test(injectionFrom(partial)?.prependContext ?? "")) {
  problems.push("a degraded bundle injected a block that reads as complete");
}

// A capped list must not read as the whole truth.
const capped = renderContext(
  { records: [{ action: "a" }, { action: "b" }, { action: "c" }], degraded: false },
  { maxRecords: 1, maxChars: 4096 },
);
if (!/2 further record/.test(capped)) problems.push("a capped list did not say what it left out");

// The bounds the plugin adds, and the actor the host supplied, reach the process it spawns.
const argsFile = `${binDir}/../args`;
process.env.READER_ARGS_FILE = argsFile;
await recall({ read: reader("empty"), timeoutMs: 4000, maxRecords: 3 }, "builder");
delete process.env.READER_ARGS_FILE;
const passed = (await import("node:fs")).readFileSync(argsFile, "utf8");
for (const expected of ["--limit 3", "--deadline-ms 2000", "--timeout-ms 3200", "--actor builder"]) {
  if (!passed.includes(expected)) problems.push(`the reader was not given ${expected}: ${passed.trim()}`);
}
// A bound an operator already chose is theirs, not this file's to replace.
if (bounds(["r", "bundle", "--limit", "1"], 5000, 8).includes("--limit")) {
  problems.push("a configured --limit was overridden");
}
if (actorFor(["r", "bundle", "--actor", "other"], "builder").length !== 0) {
  problems.push("a configured --actor was overridden");
}
// An agent id that would be read as a flag is not passed as one.
if (actorFor(["r", "bundle"], "--actor").length !== 0) problems.push("an agent id shaped like a flag was passed");

for (const problem of problems) console.log(`::error::openclaw recall: ${problem}`);
process.exit(problems.length ? 1 : 0);
JS
  plugin="$PWD/harnesses/openclaw/memory-plugin/index.mjs"
  node "$work/recall-assertions.mjs" "$plugin" "$memwork/bin" || status=1
  [ "$status" -eq 0 ] && note "injects structure; fails open on no reader, no binary, a refusal, \
garbage and no answer; and an empty match reads differently"

  echo "→ the fail-open assertions can fail: breaking each one is caught"
  # Two agents this week shipped a guard that silently allowed everything. The way that ships is
  # assertions that pass whatever the code does, so each claim is checked by breaking it on a copy
  # and requiring the run to go red.
  mutant_dir="$work/mutants"
  mkdir -p "$mutant_dir"
  survived=0
  mutate() {
    local name="$1" expression="$2" out="$mutant_dir/$1.mjs"
    sed "$expression" "$plugin" > "$out"
    cmp -s "$out" "$plugin" && {
      fail "mutant $name changed nothing, so it proves nothing"
      return
    }
    if node "$work/recall-assertions.mjs" "$out" "$memwork/bin" >/dev/null 2>&1; then
      fail "mutant $name survived: the assertions do not exercise that path"
      survived=1
    else
      note "mutant $name was caught"
    fi
  }
  # A failure that injects whatever it has: the fail-open path stops being distinguishable from a hit.
  mutate injects-on-failure 's/outcome?.kind === "recalled" ?/outcome?.kind !== "impossible" ?/'
  # A quiet store reported as a broken one: the distinction the log exists to keep.
  mutate empty-as-failure 's/answer({ kind: "empty" });/answer({ kind: "unavailable", why: "no rows" });/'
  # A lookup that ran out of time inventing an answer instead of admitting it.
  mutate timeout-invents 's|child.kill("SIGKILL");|answer({ kind: "recalled", context: "invented", count: 1 }); return;|'
  [ "$survived" -eq 0 ] || fail "the fail-open path is asserted rather than exercised"
else
  fail "node is not installed, so the recall plugin's outcome path went untested"
fi

if [ "$status" -eq 0 ]; then
  echo "glue: clean — installers parse, the hook refuses, and recall fails open"
fi
exit "$status"
