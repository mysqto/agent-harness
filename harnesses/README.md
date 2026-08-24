# Harnesses

A harness is whatever runs the model and calls the tools. This directory holds the glue for adopting
the tool policy in one, and nothing else: no rules live here.

## The split

```
spec/tool-policy.json      the rules — one file, harness-agnostic, the only source of truth
crates/harness-policy        the guard that enforces them, and one generator per harness
harnesses/<name>/            install glue for one harness: where its config goes, how to wire it
```

Adopting a harness is two pieces of work, and they are deliberately small:

1. **A translator**, in `crates/harness-policy/src/harness/<name>.rs`, turning that harness's
   tool-call payload into the neutral shape (`{"tool": …, "intents": [{"kind":"read","value":…}]}`).
   A harness that can emit the neutral shape itself needs no translator — use `--harness neutral`.
2. **An installer**, in `harnesses/<name>/install.sh`, that puts the generated config where the
   harness reads it and wires the guard as a pre-tool-use hook.

Neither piece decides anything. Every refusal comes from the policy, so two harnesses cannot disagree
about what is allowed.

## The two layers, and why both

| Layer | Mechanism | Fails when |
|---|---|---|
| 1 — tool allow/deny | the harness's own config, generated from the policy | it was never installed, or the harness does not read it |
| 2 — pre-tool-use hook | `harness-guard`, a process that exits 2 to block | it was never installed |

Layer 2 does not check whether layer 1 ran, and layer 1 does not check whether layer 2 is wired.
That independence is the point: each is a complete control on its own, and the generated config
carries the hook wiring so installing one installs both.

**How layer 2 attaches is the harness's business.** Some harnesses run a hook command and read its
exit code; others only reach the tool-call boundary from inside a plugin. Either way the guard is a
separate process the harness spawns, so the mechanism changes and the control does not — and a
harness that offers no such attachment point can carry layer 1 alone, provided its installer says so
rather than implying five layers where there are four.

A generator may **omit** a rule its harness cannot express — the hook still enforces it — but it must
never emit an *allow* the policy does not grant. Layer 1 is a convenience; layer 2 is the control.

## Checking it without a model in the loop

```sh
echo '{"tool":"read","intents":[{"kind":"read","value":"~/.ssh/id_rsa"}]}' | harness-guard check
echo $?    # 2 — blocked
```

Exit 0 means allowed, 2 means blocked. There is no code for "could not decide": an unparseable
payload, an unloadable policy and a rule violation are all answered with 2, because a guard that
opens when it is confused is not a guard.

## Contents

| Harness | Config it writes | Notes |
|---|---|---|
| `claude-code/` | `.claude/settings.json` | Path and command denies plus the `PreToolUse` hook. |
| `hermes/` | `cli-config.yaml` | The `pre_tool_call` hook only; that harness has no deny list. It reads its verdict from the hook's stdout, not the exit code. |
| `openclaw/` | nothing — it prints a fragment | The exec gate, plus a plugin that spawns the guard. A second installer wires memory recall through a plugin that owns the memory slot. |
