# OpenClaw

Wires `spec/tool-policy.json` into an OpenClaw deployment: its exec gate is layer 1, and a
`before_tool_call` plugin that spawns `harness-guard` is layer 2. A second, independent installer
wires memory: writes through the exec tool, and recall through a plugin that owns the memory slot.

## Install

```sh
setup/install.sh --harness openclaw                 # builds, installs the guard, wires this harness
harnesses/openclaw/install.sh --config ~/.openclaw/openclaw.json         # or wire the policy by hand
harnesses/openclaw/install-memory.sh --config ~/.openclaw/openclaw.json  # and recall, separately
```

Two installers because they wire two unrelated things, and because a deployment may want either
without the other: enforcement does not need memory, and memory does not need enforcement.

**Neither installer writes the config file.** That file is one large JSON5 document holding
credentials, and a merge tool that gets it wrong loses them. So each puts its plugin on disk,
generates a fragment, and prints the one validated write that merges it:

```sh
openclaw config patch --file <fragment> --dry-run   # schema-checks it, writes nothing
openclaw config patch --file <fragment>
```

`--apply` runs that for you. Either installer refuses to run it when `plugins.load.paths` already
holds entries, because a patch replaces arrays rather than extending them and dropping a load path
would silently unload somebody else's plugin — including, if both are installed, the other one's.

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
handler can return `{ block: true, blockReason }` — so `plugin/index.mjs` pipes the call to the guard
and turns a non-zero exit into that refusal. It decides nothing; adding a rule never means editing it.

The plugin imports nothing from the harness: `register(api)` on a plain default export, one
`api.on("before_tool_call", …)`, and `node:child_process`. That is deliberate — a plugin that imported
an internal module would break on an upgrade that moved it.

**The hook is bounded explicitly, because nothing bounds it by default.** Most hooks here have a
host-side default timeout; `before_tool_call` has none, so a handler that hung would wedge the tool
call for ever. The fragment therefore sets `hooks.timeouts.before_tool_call` — the setting that
overrides everything else — and the plugin sets its own, shorter budget.

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

## The read path: a plugin that owns the memory slot

Recall is wired, by a second plugin and a second installer:

```sh
harnesses/openclaw/install-memory.sh --config ~/.openclaw/openclaw.json --agent main \
  --thread-kind chat_thread --spec-dir /srv/memory/spec
```

The last two are what let a bundle name the turn rather than only its actor; see *[What a turn can
say about itself](#what-a-turn-can-say-about-itself)*. Both are optional and both are off by
default — the plugin says at load which of them is unwired.

Separate from `install.sh` because it is separate work. Everything that script emits is generated from
`spec/tool-policy.json`; recall is not a tool rule, and a policy generator emitting memory settings
would put a decision the policy has no opinion on into output the policy owns.

```json
{
  "plugins": {
    "load": { "paths": ["~/.local/share/harness/openclaw-memory-plugin"] },
    "slots": { "memory": "harness-memory" },
    "entries": {
      "harness-memory": {
        "enabled": true,
        "hooks": { "timeouts": { "before_prompt_build": 10000 } },
        "config": {
          "read": ["…/yaam-read", "bundle", "--socket", "…/main.read.sock"],
          "threadEntity": "chat_thread", "specDir": "/srv/memory/spec",
          "timeoutMs": 5000, "maxRecords": 8, "maxChars": 2000
        }
      },
      "active-memory": { "enabled": false }
    }
  }
}
```

### The hook that injects, and the one that does not

`before_prompt_build`. It is one of four hooks the harness classes as prompt injection, and the only
one that both sees the turn and can return text for it: its result type carries `prependContext`,
`appendContext` and the two system-prompt variants, and the runtime concatenates that field across
every handler before building the prompt. The plugin returns `{ prependContext }` and nothing else.

Three things it is *not*, each of which was worth ruling out:

- **`before_agent_start`** takes the same fields and is deprecated in favour of this one, with a
  runtime warning naming the replacement.
- **`llm_input`** sees the assembled prompt and is a *conversation* hook, which a plugin that did not
  ship with the harness may not register at all unless the config says
  `hooks.allowConversationAccess=true`. `before_prompt_build` is not on that list, so this needs no
  such grant.
- **`heartbeat_prompt_contribution`** contributes to an unprompted turn, not a reply to a person.

`hooks.allowPromptInjection=false` on this plugin's entry silences it — the hook is refused at
registration with a diagnostic naming the setting. That is the off switch, and it is louder than
deleting the entry.

### Owning the slot is what stops there being two memories

`plugins.slots.memory` holds one plugin id. A plugin declaring `kind: "memory"` that the slot does not
name is **disabled outright**, with `memory slot set to "…"` recorded as its reason — so naming this
plugin turns the built-in memory backend off. That is the point of taking the slot rather than merely
registering the hook: a plugin can inject context without owning anything, and then two things answer
"what do we remember" from two stores.

Leaving the slot unset is not neutral either. With no id in it, the first memory-kind plugin the loader
reaches wins and the rest are disabled with `memory slot already filled by "…"` — a working config
whose answer depends on load order. So the fragment always names the slot.

`kind: "memory"` is declared twice, in the manifest and on the default export, and they must agree:
the loader takes the export's word for it and warns about a mismatch, and the slot naming a plugin
that is not of this kind is a startup warning and no memory at all.

The recall sub-agent is a *different* plugin and the slot does not touch it, so the fragment disables
it by name. It would otherwise run a bounded model call at this same hook every turn, looking for
memory tools that went away with the backend the slot displaced.

### What the slot plugin may implement, and what this one does not

Owning the slot grants registrations nothing else may make — the interesting one being a memory
runtime: a `getMemorySearchManager` returning an object with `search`, `readFile`, `status`, `sync`
and embedding and vector-store probes. **This plugin registers none of it, deliberately.** That
interface describes a file corpus with an embedding index: hits carry a path, a start and end line
and a snippet, and `readFile` returns text. Reads here return a record's frontmatter and no body at
all, so every one of those fields would have to be invented. A manager that answered with fabricated
paths and empty snippets is precisely the failure this plugin exists to avoid.

The cost is real and worth stating: the `memory_search` and `memory_get` tools belong to the built-in
backend, so taking the slot removes them. The agent *receives* recall and can no longer ask for it.
Host paths that want a search manager get an explicit "memory plugin unavailable" rather than an empty
result, which is the right shape of failure but still a failure.

`memory.backend` is **not** the slot and must not be set to match it: its two values, `builtin` and
`qmd`, select the engine the built-in backend uses. The fragment emits none. A deployment already
carrying `qmd` there is left inert rather than broken — the startup path asks the slot owner for a
backend config, gets nothing, and skips the agent — but the key describes a backend that is no longer
loaded, and it should come out.

### Recall fails open, and that is the opposite of layer 2

A guard that cannot decide must block. A memory lookup that cannot answer must let the turn proceed.
An agent that stops working because its memory service is down is worse than an agent with no memory,
so a reader that is unconfigured, unspawnable, slow, refused, or answering something unreadable
produces no context and a warning — never an error, and never invented context.

The harness agrees in both directions, which is why each plugin can be short: a thrown
`before_tool_call` handler becomes a blocked call, and a thrown `before_prompt_build` handler is
logged and the turn continues. Only `before_agent_run` is fail-closed by default.

What must **not** blur is which kind of nothing arrived. "The service matched nothing" and "the
service could not be asked" call for opposite reactions, so they are separate outcomes in the code
and separate lines in the log:

```
harness-memory: the memory service matched nothing; the turn proceeds with no recalled context
harness-memory: recall unavailable, the turn proceeds without memory: …
```

The first is a fact about the store, at info. The second is a fact about the plumbing, at warn. A
deployment that cannot tell them apart cannot tell a quiet week from an outage — and a recall plugin
that silently retrieves nothing is the same bug as a guard that silently allows everything.

### Bounded three times over, innermost first

The lookup sits in front of a reply, so a slow read is a conversation that looks hung. Unlike
`before_tool_call`, this hook *does* have a host default — 15 s — but 15 s in front of a reply is too
long, and the host's timeout says only that a hook failed. So:

| Bound | Value | Who answers when it fires |
|---|---|---|
| `--deadline-ms` | half the budget | the service, naming the source it could not consult |
| `--timeout-ms` | four fifths | the reader, naming the socket that went quiet |
| the plugin's budget | `timeoutMs`, default 5 s | this plugin, killing the reader |
| `hooks.timeouts.before_prompt_build` | twice the budget | the host, generically |

Nested so the most specific answer available is the one that lands. A bound already named in the
configured argv is left alone: it was chosen for a reason this plugin cannot see.

### Why `bundle`, and not `search` or `records`

`bundle` is the read that exists for this: it composes context for one request out of an actor's
recent activity and any named entities, in one capped set. Two things it returns that the others do
not decide it —

- **`degraded`, with `omitted`.** A bundle whose sources ran out of time says so and names them. That
  is the difference between "nothing to recall" and "could not consult", which is exactly the
  distinction the log has to keep; a `records` query that came back short is indistinguishable from
  one that came back empty.
- **`token_estimate`.** The cost of what is about to go into a prompt, measured over the rows being
  returned. It is logged, so an operator can see what recall charges per turn.

`--actor` is the agent the host names for the run, appended when the argv does not already name one;
the socket decides what that agent is allowed to see, so asking about an actor never widens scope.
`search` was the alternative and needs a needle, which means deriving one from the user's prose — a
step with no honest implementation that does not put a model in this path. Prose *is* read now, and
the reason that is not the same decision is below: it is read by the deployment's own extraction
rules, inside the reader, and what comes out are lookup keys rather than an answer.

A partial bundle is rendered as partial, and a capped list says how many rows it left out. A short
list that reads as the whole truth is a list the model will act on.

### What a turn can say about itself

A bundle composes context out of **entities** and an **actor**. The first version of this plugin sent
the actor and nothing else, which meant every turn asked "what has this agent done lately" — and in a
deployment whose records were written by an importer and a bot, under names no live turn ever runs
as, the honest answer was nothing. Every time. It logged `matched nothing`, which was true, and it
never once looked wrong.

The hook's payload is the fix, and it is worth being exact about what it does and does not carry.
`before_prompt_build` receives `(event, ctx)`: `event` has `prompt` and `messages`, `ctx` has
identifiers and no content. There is **no thread field on either** — nothing named `threadId`,
`thread_ts` or `conversation`. Two things are reachable, and both become lookups:

| What | Where it comes from | What it becomes |
|---|---|---|
| the conversation | `ctx.channelId` | `--entity <threadEntity>:<conversation>/<thread>` |
| the message | `event.prompt` | `--infer-entities <specDir> --infer-from <text>` |

**The thread arrives inside the conversation id, not beside it.** The host builds `ctx.channelId`
from the session key, and a threaded run's key ends `…:thread:<id>`; splitting on that is the only
route from this hook to a thread. It is the one shape here that belongs to the harness rather than to
the deployment, and a harness that changed it would make recall go quiet rather than fail — so a turn
that yields no thread is a fact the log carries, and two of the mutation tests exist to prove the
assertion about it can fail.

**A caveat that will bite a deployment with imported history.** The host case-folds the conversation
half of that id for most chat providers. An entity kind whose `normalise` is `[trim]` therefore will
not match an identifier that was stored with its original case — the two are different keys. The
reconciliation belongs in the deployment's own `spec/entities.yaml` (fold the case there, or fold it
in the importer); this plugin will not invent a case it was not given, because guessing one would
produce keys that look right and match nothing.

**Reading the message is a read-time inference, and that is a different bar from a write.** The
reader's `--infer-entities` runs the deployment's own `extractors.yaml` over `--infer-from`. At write
time an inferred reference becomes a stored join key, which is why those rules stay below the
high-confidence floor and why a bundle joins only on references a record states at `1.0`. Here the
output is a lookup key: it matches records that reference it at full confidence, or it matches
nothing. A wrong guess costs one wasted lookup rather than a permanent falsehood, so this may infer
where a writer may not — and nothing about what reaches a bundle has been loosened.

Both settings are off unless configured, and neither has a default this harness could invent: an
entity vocabulary and a spec directory both belong to the deployment. The plugin says at load which
of them is unwired, at info, because an operator wondering why recall is thin should not have to read
the source to find out.

```
harness-memory: no thread is looked up: set config.threadEntity to the entity kind this deployment files conversations under
harness-memory: the message is not read for entities: set config.specDir to the deployment's spec directory
```

A flag an operator already put in the configured argv is left alone, as the bounds are: `--entity`,
`--infer-entities` and `--infer-from` in the config are that operator's choice, and this adds none of
its own beside them.

### Checking recall

```sh
yaam-read bundle --socket ~/.local/state/harness/sockets/main.read.sock --limit 3
```

Expect JSON with a `records` array; an empty one is a valid answer and exits 0. Exit 9 means nothing
is serving that socket — check the sidecar, and check this is the `.read.sock` and not the record
socket beside it. No key is involved at any point: the sidecar signs on the caller's behalf, which is
why the plugin can spawn a reader and hold nothing.

Check the two turn settings separately, because each fails silently on its own. The reader's dry run
needs no socket and no service:

```sh
yaam-read bundle --dry-run --entity chat_thread:c0example/1700000000.000100   # the thread half
yaam-read bundle --dry-run --infer-entities /srv/memory/spec \
          --infer-from "any news on ticket PROJ-42?"                          # the message half
```

The second should print a request whose `entity` parameter names what that sentence mentions. If it
prints one with no `entity` at all, the deployment's `extractors.yaml` anchors nothing in that
sentence — which is a rules question, not a wiring one. And an empty answer from the live socket now
says what it asked about, which is the first thing to check when it stays empty:

```
harness-memory: the memory service matched nothing (asked about chat_thread:c0example/…); the turn proceeds with no recalled context
harness-memory: the memory service matched nothing (asked about nothing in particular); …
```

The second line is a wiring problem. The first is a store that has nothing about this thread yet.

```sh
openclaw plugins doctor
openclaw plugins inspect harness-memory --runtime --json
```

Restart the gateway first. A load path pointing at nothing loads silently, and a slot naming a plugin
that did not load is one warning in a startup log.

### The route that looked like a setting, and was not

Worth keeping, because it cost a day and the trap is still there. The recall sub-agent's `toolsAllow`
names the tools it may call, so the apparent integration is to allow it `exec` and append instructions
for querying the store. But `exec` is on a hardcoded reserved list that `toolsAllow` entries are
filtered against, and a filtered entry is dropped **without an error**: every entry is stripped, the
list falls back to the provider default, and what is left is a config that looks like a memory
integration and is not one. `read`, `write` and `web_fetch` are on that same list. `promptAppend`
without a callable tool is instructions to an agent that cannot act on them.

The upstream fix is to make the filter loud — a rejected config, or a warning naming the dropped
entry, would have made that a startup error instead of a plausible-looking nothing.

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

### Code mode is refused, not screened

If code mode is on, an `exec` call can carry a *program* instead of a command line — and the harness
mirrors it into the same `command` field, so it looks translatable. It is not. `sh('cat ~/.ssh/id_rsa')`
reads as the program `sh` with a quoted argument and would be **permitted**, while the shell line it
builds would not be; and a program can assemble a command at runtime out of pieces no static reading
joins up. So the guard refuses any call marked `code_mode_exec` outright and says why.

That is a real restriction: with this harness wired, code mode does not work. Turn it off, or describe
code in the policy before turning it on. Screening it as though it were a command line was the
alternative, and it is the one that answers wrongly in the dangerous direction.

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

That checks the guard. Checking the *plugin* is a separate question, and worth asking: a load path
pointing at nothing loads silently.

```sh
openclaw plugins doctor                                     # load errors, if any
openclaw plugins inspect harness-tool-policy --runtime --json   # imports it, lists what it registered
```

Restart the gateway first — changes to plugin code, enablement or `plugins.load.paths` do not take
effect until it restarts. `openclaw plugins validate` is not the check to use here: it only handles
tool plugins and errors on anything else.

The plugin directory is discovered the ordinary way — a directory holding `openclaw.plugin.json` and
an `index.mjs`, named in `plugins.load.paths`. No packaging step and no build. Two things the loader
insists on, both of which the installed manifest satisfies: an `id` matching the one the entry
exports, and a `configSchema`; a manifest missing either is skipped rather than reported loudly.
