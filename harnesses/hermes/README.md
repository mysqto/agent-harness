# Hermes

Wires `spec/tool-policy.json` into a hermes config as a `pre_tool_call` hook. That hook is layer 2.
There is no layer 1 here, and the reason is in [What layer 1 cannot say](#what-layer-1-cannot-say).

## Install

```sh
setup/install.sh --harness hermes                  # builds, installs the guard, wires this harness
harnesses/hermes/install.sh --target ~/.hermes     # or wire it by hand
```

The installer never overwrites an existing config file — that file holds credentials. If one is
there, it writes `cli-config.harness-policy.yaml` beside it and prints the merge. It also refuses,
non-zero, when the target directory does not exist: creating it would put a hook fragment somewhere
nothing reads and report success.

## What is generated

The config is YAML, so the fragment is YAML:

```yaml
hooks:
  pre_tool_call:
    - command: "harness-guard check --harness hermes --policy …"
      timeout: 30
```

Regenerate at any time — the policy is the source, this is output:

```sh
harness-guard emit --harness hermes
```

Three things in those four lines are deliberate.

**`pre_tool_call`, and only that.** It is the one event whose block directive stops a tool call. The
event names are validated against a fixed list and a name that is not on it produces a log warning
and nothing else, so a typo here is an adapter that installs cleanly and enforces nothing.

**No `matcher`.** A matcher is a regex on the tool name, and an entry carrying one fires only for the
tools it matches. Every other tool then runs unchecked. An absent matcher matches everything, which
is the only setting that makes this a control.

**A generous `timeout`.** A hook that times out is read as having no opinion — the call proceeds. The
guard answers in milliseconds; 30 seconds is far above that on purpose, because the cost of waiting
is a pause and the cost of timing out is an unchecked tool call.

## The refusal has to be said out loud

This is the one thing that will make the adapter look installed and enforce nothing.

The runtime does not decide from the hook's exit code. It parses the hook's **stdout**, and empty or
non-JSON stdout means *no opinion* — whatever the process exited with, and it logs the non-zero exit
as a warning while allowing the call. So the guard's `exit 2` is not, on its own, a block here.

The hermes path therefore prints the verdict:

```json
{"decision":"block","reason":"terminal refused: blocked by private-keys: private key material (…)"}
```

Which the runtime normalises internally to its own shape. It is emitted for *every* block on this
harness, including the ones that are not rule violations: a payload that will not parse, a policy
that will not load, a bad command line. Those are the likeliest blocks of all — they are what the
wrong `--harness` produces — and a block delivered only as an exit code would be invisible.

`crates/harness-policy/tests/guard.rs` asserts this against the built binary rather than in-process,
because the interface is a real process's stdout.

## What layer 1 cannot say

Nothing, and that is not a shortcut. This runtime has no tool allow/deny config to generate into: it
configures which *scripts* may run, not which tools the model may call. So the generator emits the
hook wiring and no rules, and the hook carries all of them — the secret and protected paths, the
command rules, workspace containment, and the egress allowlist.

`harnesses/README.md` allows exactly this: a generator may omit a rule its harness cannot express,
because the hook still enforces it. What it may never do is emit an *allow* the policy does not
grant, and a fragment with no allow list emits none.

The practical consequence is that this harness has one control rather than two, so the checks below
matter more here than they do for a harness with a deny list behind them.

## Its own allowlist is not this policy

The runtime keeps `shell-hooks-allowlist.json` in its home, with `revoke` and a first-use consent
prompt. It looks like a tool-permission layer and it is not one. Read it against
`spec/tool-policy.json` and they do not overlap at a single point:

| | `spec/tool-policy.json` | the runtime's allowlist |
|---|---|---|
| Answers | may the agent do this? | may this script run at all? |
| Keyed on | paths, programs, hosts | `(event, command)` pairs |
| Consulted | on every tool call | once, at startup, per pair |
| Enforced by | the guard | the runtime's hook registration |

They complement rather than conflict: the allowlist is a **precondition** of layer 2, not a peer of
it. That is also its sharp edge, and it cuts one way only —

- An unapproved hook is **skipped**, with a log warning and no error. On a non-interactive run with
  no consent recorded, the config is present, the fragment is correct, and nothing is enforced.
  Approve it once at a prompt, or pass the runtime's accept-hooks flag or `HERMES_ACCEPT_HOOKS=1` for
  the run that registers it.
- The approval is keyed on the **exact command string**. Re-running the installer with a different
  guard path or a different `--policy` produces a different pair, which needs approving again.
- Its safe mode skips hook registration entirely, along with plugins and MCP. A troubleshooting run
  is a run with no layer 2.
- Do not set the config's auto-accept flag to solve this. It approves every hook command, not this
  one, and turns a consent gate into nothing.

The one thing in it worth having: it records the hook script's mtime at approval, so a script edited
under a standing approval is detectable. That is a control this repo's policy does not have, on a
question this repo's policy does not ask.

The runtime's other guardrail — the repeated-failure and no-progress circuit breaker — overlaps
nothing here either. It counts retries within a turn, not permissions, and its hard stops are off
unless enabled.

## Checking the wiring

```sh
echo '{"hook_event_name":"pre_tool_call","tool_name":"terminal",
       "tool_input":{"command":"cat ~/.ssh/id_rsa"},"session_id":"s","cwd":".","extra":{}}' \
  | harness-guard check --harness hermes; echo "exit $?"
```

Expect `exit 2`, a refusal naming the `private-keys` rule on stderr, **and** a
`{"decision":"block",…}` object on stdout. Exit 2 with an empty stdout is the failure mode this whole
harness is arranged around, so check for the object and not only the code.

If you get `exit 0`, the guard is reading a different policy than you think — pass `--policy`
explicitly and try again. If you get `exit 2` and `malformed hook payload`, the payload is not the
envelope this translator reads; the message names the field.

## What the translator reads, and what it does not

Intents come from the fields *present* in `tool_input`, not from a table of known tools, so a tool
added tomorrow still gets its `command`, `url` or path checked. Path fields hold either one path or a
list of them, which is how the multi-file readers arrive.

The envelope itself is checked strictly, because it is declared: all six fields are built on every
firing, so one missing means the payload came from somewhere else. A missing `hook_event_name`, a
`tool_input` that is not an object — which is what the runtime sends when the arguments were not a
mapping — or a known field holding a shape the translator cannot read are all **refused**, not read
as a call with nothing to check. `crates/harness-policy/src/call.rs` documents why: that exact bug
shipped, and zero intents is nothing to deny.

Two limits worth knowing:

- **A field name the translator does not list yields no intent.** `PATH_FIELDS` in
  `crates/harness-policy/src/harness/hermes.rs` is the list; a tool naming its path something else
  needs one line added there.
- **Code passed to a code-execution tool is not parsed as a command line.** Splitting a Python
  program on shell operators produces nonsense, so it is not attempted. A shell command line is
  checked thoroughly; a program that shells out from inside an interpreter is not, and that is what
  the layers below the guard are for.
