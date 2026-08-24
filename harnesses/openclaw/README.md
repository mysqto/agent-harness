# OpenClaw

Wires `spec/tool-policy.json` into an OpenClaw deployment: its exec gate is layer 1, and a
`before_tool_call` plugin that spawns `harness-guard` is layer 2.

## Install

```sh
setup/install.sh --harness openclaw                 # builds, installs the guard, wires this harness
harnesses/openclaw/install.sh --config ~/.openclaw/openclaw.json   # or wire it by hand
```

The installer **never writes the config file**. That file is one large JSON5 document holding
credentials, and a merge tool that gets it wrong loses them. So the installer puts the plugin on disk,
generates the fragment, and prints the one validated write that merges it:

```sh
openclaw config patch --file <fragment> --dry-run   # schema-checks it, writes nothing
openclaw config patch --file <fragment>
```

`--apply` runs that for you. It refuses to run when `plugins.load.paths` already holds entries,
because a patch replaces arrays rather than extending them and dropping a load path would silently
unload somebody else's plugin.

## What is generated

```json
{
  "tools": { "exec": { "security": "allowlist", "ask": "on-miss" } },
  "plugins": {
    "load": { "paths": ["~/.local/share/harness/openclaw-plugin"] },
    "entries": {
      "harness-tool-policy": {
        "enabled": true,
        "config": { "guard": ["…/harness-guard", "check", "--harness", "openclaw", "--policy", "…"] }
      }
    }
  }
}
```

Regenerate at any time — the policy is the source, this is output:

```sh
harness-guard emit --harness openclaw
```

The `${plugin_dir}` placeholder in that output is the installer's to fill in. The generator cannot
know where the plugin was installed, and a guessed path would be a load path pointing at nothing:
no plugin, no error, no enforcement.

## Layer 2 is a plugin, not a hook command

This harness has no hook-command setting. What it has is a plugin hook, `before_tool_call`, whose
handler can return `{ block: true, blockReason }` — so `plugin/index.mjs` is thirty lines that pipe
the call to the guard and turn a non-zero exit into that refusal. It decides nothing; adding a rule
never means editing it.

**Every failure blocks, on both sides of the boundary.** A guard that is not configured, cannot be
started, or does not answer in time is the same answer as a guard that refused, because "we could not
tell" and "it was fine" are different things and only one of them is safe. The plugin never throws and
never resolves to "allow" on a failure, and the harness agrees: a `before_tool_call` handler that
throws is caught and turned into a blocked call, not a permitted one. The budget the plugin gives the
host is twice the one it enforces on itself, so the plugin's own refusal — which carries a reason
naming the policy rule — always lands before a host-side hook timeout could answer with a generic one.

## The write path needs nothing new

Agents record what they did by running `yaam-emit` through the exec tool. Two settings the policy has
no opinion on, so the installer prints them rather than emitting them:

```sh
openclaw approvals allowlist add --agent main "$HOME/.local/bin/yaam-emit"
openclaw config set env.vars.YAAM_SOCKET "$HOME/.local/state/harness/sockets/main.sock"
openclaw config set env.vars.YAAM_AGENT  "main"
```

The socket in the environment rather than on the command line is deliberate: an allowlist pattern
that had to match a socket path would break the first time the path changed.

## What this does *not* wire: the read path

**Recall is not wired, and cannot be from configuration alone.** The obvious route does not work, and
it fails silently, which is worse than failing.

The `active-memory` extension runs a bounded memory sub-agent before eligible replies and injects what
it finds into prompt context. Its `toolsAllow` names the tools that sub-agent may call — so the
apparent integration is to allow it the exec tool and append instructions for querying the store. But
`exec` is on a hardcoded reserved list that `toolsAllow` entries are filtered against, and a filtered
entry is dropped without an error. Configure `toolsAllow: ["exec"]` and every entry is stripped, the
list falls back to the provider default, and you are left with a config that looks like a memory
integration and is not one. `read`, `write`, `web_fetch` and the rest of the general toolset are on
that same list.

So the sub-agent can be told about the store and given nothing to reach it with. `promptAppend`
without a callable tool is instructions to an agent that cannot act on them.

What would make recall work, in rough order of how much it asks of upstream:

1. **A memory plugin.** The reserved list exists to stop the recall sub-agent reaching general tools;
   the memory tools it *is* allowed by default come from whichever plugin owns the `plugins.slots.memory`
   slot. A plugin owning that slot and backing those tool names with the store is the intended shape,
   and needs no upstream change — but it is a plugin to write, not a setting to set.
2. **A non-reserved tool name.** `toolsAllow` accepts any name not on the reserved list, so a plugin
   registering its own query tool could be allowed to the sub-agent directly.
3. **Upstream: make the filter loud.** An entry silently dropped is the whole reason this is a trap.
   A rejected config, or a warning naming the dropped entry, would have turned a plausible-looking
   integration into an error at startup.

Until one of those exists, this harness wires writes and enforcement. Recall is absent, and the
installer says so rather than implying otherwise.

## What layer 1 here cannot say

The exec gate is an **allowlist** of command patterns held in the host approvals file, not a deny list
that inspects a command line. A deny policy does not translate into an allowlist, so what is generated
is the *posture* — unlisted commands ask, and an unanswered ask is a refusal — and the guard is what
reads the policy's denied programs. Consequently:

- **Denied programs.** Not expressible. `gateway.nodes.denyCommands` looks like the place for them and
  is not: it matches node command *ids* (`system.run`) exactly and never inspects shell text inside
  one, so `passwd` or `mkfs` listed there would match nothing. The harness's own audit flags
  pattern-like entries for exactly this reason. The generator emits none, and a test asserts it emits
  none — an entry that matches nothing is worse than an absent one, because it reads as protection.
- **Secret and protected paths.** Nothing in this config file speaks about paths at all.
- **The egress allowlist.** No per-host gate exists to generate.

All three are enforced by the guard, which sees the command line, splits it on every shell operator,
looks through `sudo` and `env`, recovers redirection targets as writes, and folds in the host's own
`derivedPaths` for structured edit envelopes.

`tools.exec.security` also accepts `deny` and `full`, and `tools.exec.timeoutSec` bounds how long a
command may run. Neither is emitted: `full` would remove layer 1 entirely, and the policy declares no
timeout — inventing one here would be a rule living in a harness directory, which is the one thing
these directories may not hold.

Note that `security` and `ask` are the legacy spelling of a newer single `mode` key, and the harness
**hard-rejects** a config carrying both. The fragment uses `security` and `ask` because any deployment
old enough to need it already has those two set; emitting `mode` would make an existing config fail
validation.

## Checking the wiring

```sh
echo '{"toolName":"exec","params":{"command":"cat ~/.ssh/id_rsa"}}' \
  | harness-guard check --harness openclaw; echo "exit $?"
```

Expect `exit 2` and a refusal naming the `private-keys` rule. If you get `exit 0`, the guard is
reading a different policy than you think — pass `--policy` explicitly and try again.

That checks the guard. To check the *plugin* is loaded, restart the gateway and confirm it appears in
`openclaw plugins`; a load path pointing at nothing loads silently.

The plugin directory is discovered the ordinary way — a directory holding `openclaw.plugin.json` and
an `index.mjs`, named in `plugins.load.paths`. No packaging step, and nothing imported from the
harness itself, so the plugin cannot break on a harness upgrade that moves an internal module.
