# OpenClaw

Wires `spec/tool-policy.json` into an OpenClaw deployment: a `before_tool_call` plugin that spawns
`harness-guard` is layer 2, and its exec gate is layer 1 wherever that gate can be emitted without
stopping the agents. A second, independent installer wires memory: writes through the exec tool, and
recall through a plugin that owns the memory slot.

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

Layer 2, and nothing else. **The exec gate is not in there, and leaving it out is deliberate** — see
*[The exec gate is emitted with its pre-approvals, or not at
all](#the-exec-gate-is-emitted-with-its-pre-approvals-or-not-at-all)*. Ask for the gate by naming the
commands the agents may run without being asked, one argv word per flag:

```sh
harnesses/openclaw/install.sh --config ~/.openclaw/openclaw.json \
  --backend-arg --allowedTools --backend-arg 'Bash(git status:*),Read'
```

which puts both halves in, together:

```json
{
  "tools": { "exec": { "security": "allowlist", "ask": "on-miss" } },
  "agents": { "defaults": { "cliBackends": { "claude-cli": {
    "args": ["--allowedTools", "Bash(git status:*),Read"]
  } } } }
}
```

One word per flag rather than one flag holding a line, because a pattern like `Bash(git status:*)`
carries a space: re-split, it pre-approves two halves that are neither of them a command, which reads
like a pinning and pre-approves nothing.

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

### The hook sees the harness's own tools, not the model's

`before_tool_call` fires for calls this harness dispatches. It does **not** fire for the tools an
agent's own runtime provides. Where agents run through the Claude CLI backend, the model reaches the
shell through that runtime's native `Bash`, and the host's relay carries an adapter for the `codex`
CLI's tool events and none for the `claude` one — so those calls never become a hook event and the
guard never sees them. Measured, not reasoned about: the guard blocks `cat ~/.ssh/known_hosts` as an
`exec` tool call, and the same command through native `Bash` runs to completion with this plugin
loaded and enabled.

So, plainly: **on a `claude` backend the shell is not covered here.** Not by layer 2, which is not
called; and not by layer 1 either, for the separate reason below. An operator who reads "a hook at
the tool-call boundary" as covering tool calls generally has a hole, and its shape is the bad one —
nothing fails, nothing is logged, and the refusal that never happened looks exactly like a policy
with nothing to refuse.

What the guard does still cover is every call the harness dispatches itself: its own `exec`, `read`,
`write`, `web_fetch`, `apply_patch`, and whatever a later release adds, since intents come from the
fields present rather than from a table of known tools. That is worth having and it is not the same
as covering the shell.

Closing the rest means wiring the guard into the other runtime as well, which is what
`harnesses/claude-code/` generates from this same policy: a `PreToolUse` hook that sees native
`Bash`. Two installs, one policy, two runtimes handing the same guard their calls. Whether a CLI the
harness spawns reads a particular settings file is a deployment question — check it rather than
assume it, the same way a load path pointing at nothing is worth checking.

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
  --thread-kind chat_thread --spec-dir /srv/memory/spec --digest-days 14
```

The middle two are what let a bundle name the turn rather than only its actor; see *[What a turn can
say about itself](#what-a-turn-can-say-about-itself)*. The last is the one block here that is not
about the turn at all; see *[The session-opening
digest](#the-session-opening-digest-and-why-it-is-third)*. All three are optional and all three are
off by default — the plugin says at load which of them is unwired.

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
          "digestDays": 14, "digestMaxRecords": 12, "digestMaxChars": 1200,
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
`search` was the alternative and needs a needle, which means deriving one from the user's prose.
This file used to say that had no honest implementation short of putting a model in the path. That
was too strong, and `search` now runs as a *fallback* — see below. What stands is the ordering:
`bundle` is the read that carries the question, and search is what is left when it missed.

A partial bundle is rendered as partial, and a capped list says how many rows it left out. A short
list that reads as the whole truth is a list the model will act on.

### The search fallback, and why it is second

A bundle matches on keys. Where a deployment has records with no entity references at all — an
imported corpus, most obviously — no key reaches them and no amount of inference invents one. That is
not a store with nothing in it, and recall reporting `matched nothing` says the same words for both.

So a bundle that matched nothing is followed by one `search`, on the same reader and the same socket
with one word swapped. Three things keep it from being a second, sloppier bundle:

- **It says which read answered.** The block carries a different heading: records that *mention* the
  words in a message, which may not be records *about* them. A model told otherwise presents a
  keyword hit as an established connection, and that is the failure mode of ranked retrieval.
- **The needle is built, not passed through.** Every term is quoted and joined with `OR`, and the
  framing words a question is made of (`any`, `knowledge`, `this`, `remember`) are dropped rather
  than searched for. Quoting is not cosmetic: the needle is a match expression the index parses, so
  an unquoted `?` from an ordinary question is a syntax error that refuses the whole read. A message
  with nothing but framing in it produces no needle and no second lookup.
- **The needle is built from the message, and `event.prompt` is not the message.** The host prepends
  an envelope — on this deployment one RFC-1123 timestamp, on the line above what the person wrote.
  It arrives as prose and reads as prose, so for as long as it was left on, `needleFrom` turned
  `Zzyzxqq` into `"Fri" OR "Aug" OR "2026" OR "GMT" OR "Zzyzxqq"` and the fallback ranked the
  calendar. Measured on the live store before the fix: those four date terms matched **36 of 73
  records on their own**; a bare-identifier turn came back with 8 records of which **1** named the
  identifier; a greeting came back with 8 of which **1** held any of its words. All of it was
  injected under a heading claiming the records mention words in the message.

  So the envelope comes off in `turnOf`, at the one function that reads the payload, rather than in
  `needleFrom`. It is not the message for the *bundle's* `--infer-from` either, and a fix a layer
  later would leave the reader inferring lookup keys from a date. A leading line is framing when
  every word in it names a moment — a weekday, a month, a year, a timezone, a run of digits — and at
  least one of them actually is one. Only leading lines, only while something is left below them, and
  at most four, so a pasted log stays the message it is. Deliberately **not** `Date.parse`, which
  accepts `PROJ-2087` as a date in the year 2087: a classifier that errs towards deleting the message
  is the wrong kind of general, and the line it would delete is the line this fallback exists for.
- **Calendar words are not terms, wherever they came from.** A second rule, in `needleFrom`, for a
  different reason: the envelope rule is about *whose words these are*, this one about *what a word
  can distinguish*. Every record carries a timestamp, so `"2026"` is a term half a store matches —
  36 of 73 here — whether the host wrote it or a person did. Weekday and month names, bare years, ISO
  dates and timezone abbreviations are dropped as terms. Years are bounded to `19xx`–`21xx`, so an
  order number of four digits is not quietly read as one.
- **It shares one deadline.** The fallback takes what is left of the budget the bundle did not use,
  and is skipped below a floor. The outer bound this hook registers is what stands between recall
  and a reply that looks hung, and a fallback that could double the wait would spend a bound
  somebody else set.

A fallback that fails is still an empty bundle rather than an outage: the precise read succeeded and
found nothing, which is an answer. `config.searchFallback: false` turns it off for a deployment that
wants only what its keys support.

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

### The session-opening digest, and why it is third

An agent that has to be asked before it remembers anything starts every session blind. The fix other
systems ship is a digest injected at session start — date-grouped recent activity, arriving without
being asked for — and it is worth having here. What it costs is what this section is mostly about,
because the hook that can inject it fires on the wrong schedule.

**The failure this design prevents is a digest on every turn.** `before_prompt_build` runs in front of
every message a person sends, not once when a session opens. Recall on this deployment already spends
about eleven hundred tokens a turn; a "here is what has been happening" block repeated beside it is
that cost again, on every message, for a paragraph that does not change between them. And it has no
symptom — it looks exactly like the feature working, only more often. Two mutation tests exist for
that one failure.

`before_agent_run` is the session-shaped hook, and it is not the answer: it is the one hook the
harness runs **fail-closed**, so a digest that threw there would stop the agent running at all.
Recall's whole posture is that a memory lookup which cannot answer must let the turn through, and that
posture does not survive moving to a hook where a thrown handler is a blocked run. So the digest stays
on `before_prompt_build`, behind a fence:

| Gate | Where it comes from | What it rules out |
|---|---|---|
| `config.digestDays` is set | the config | a deployment paying for a block nobody chose |
| `event.messages` is empty | the hook payload | every turn after the session's first |
| the session is unseen | this process | a backend that hands over an empty history each run |
| the bundle found nothing | this turn's own reads | spending the turn's tokens twice |
| the shared deadline has room | the budget | an unasked-for read extending somebody else's wait |

**The first-turn signal is read off the payload, not guessed.** `event.messages` is the session's
prepared history, which the host passes *beside* `event.prompt` rather than including this turn in —
so an empty one is the turn that opens the session. That is honest, and it is not trusted alone: one
backend here builds that array per run and appends to it as the run proceeds, where an empty history
is the first hook *call* rather than the first turn. So the payload signal is intersected with process
memory of the sessions already offered a digest, keyed on `ctx.sessionKey`, and both must agree. A
gateway restart forgets that memory, and a session running across one gets a second offer. That is the
cheap direction to be wrong in — one extra block on one turn — and the expensive direction is ruled
out by the payload signal, which a restart does not touch. A turn whose payload names no session at
all is never an opening: a turn this cannot tell apart from the next one is exactly the turn that
would become every turn.

**A bundle takes the turn; a ranked search does not.** That is the budget rule between the two, and
it is the one decision here the measurement made rather than the design.

A bundle is the composed answer to the question actually asked, so where it answers, nothing
unasked-for goes in beside it and the window is not even read. The fallback is a weaker claim by its
own heading — records that *mention* the message's words and may not be about them — and a turn
holding only that has not had its question answered; it has been handed a rank. Background it can act
on is worth more there, not less.

The first version of this yielded to any recall at all, which is the obvious rule and would have
shipped a feature that never fired once. **This host prefixes a timestamp to `event.prompt`**, so the
needle a live turn built read

```
--query "Fri" OR "Aug" OR "2026" OR "GMT" OR "Zzyzxqq"
```

and the fallback matched today's records on the *date*, on every turn, whatever the person asked. Any
rule that let that take the space would have gated the digest off on a keyword hit against the clock.

That envelope is gone now — the measurement it was waiting for was taken, and the needle is built
from the message rather than from the payload; see the fallback section above for the numbers and the
rule. **The budget rule does not change with it**, and it is worth being clear why, because the
reading that says "the fallback is honest now, so let it take the turn" is the wrong one. A search
was never demoted for being *wrong*; it was demoted for being a *rank*. Its heading still says these
records mention the message's words and may not be about them, and that is still not an answer to the
question. What the fix changed is how often the rank is worth reading, not what kind of claim it is.

What the fix did change is how often the fallback returns anything at all. Re-measured on the same
store: a turn naming nothing keeps its 8 records because its own prose is generic (`refund` alone
matches 21 of 73 here), but a greeting drops from 8 records to 1, and a bare identifier from 8 to 1 —
the one record that actually names it. A digest now shares an opening turn with far less noise, and
on some turns with nothing at all.

The cost is that an opening turn can carry both blocks. It is bounded twice — at most once per
session, and by two ceilings that do not share. `digestMaxRecords` and `digestMaxChars` default below
recall's own, because a window read returns a window rather than a match and is the likelier of the
two to be cut. The stronger claim is rendered first.

**One read failing does not cost the turn the other.** They fail independently, in both directions,
and each direction has a mutant:

- A window read that could not be made leaves the outcome exactly as recall left it, down to the
  kind. An empty store stays `empty`, at info. Reporting it `unavailable` because a read nobody asked
  for was refused would call a working store broken, and put an outage's noise level on an absence
  that costs the turn nothing.
- A bundle that could not be asked does **not** skip the digest. `unavailable` means that read was
  refused, not that the socket went away, and the window read is a different question over the same
  socket. Where it answers, the turn gets a digest and the log still says recall was unavailable.

**A third heading, weaker again than the second.** The two existing blocks each make a claim about
this message: one composed around its keys, one ranked on its words — and the second says so, because
a model told otherwise presents a keyword hit as an established connection. A digest is not about the
message at all, so it says that first, and then says the thing this deployment has to say out loud:

```
Recent activity in this deployment's memory, grouped by date. This is background, not an answer:
nobody asked for it and none of it is necessarily about this message. Record structure only — who
acted, when, and what they referenced. It does not say what any of it was about, and this store
holds no prose that could.
```

That last clause is the honest limit, and it is not a gap waiting to be filled. Every read here
returns frontmatter, deliberately and at every layer, so a digest can say that `deploy_bot` deployed
`example/service@1a2b3c4` successfully on the 28th. It cannot say what the deploy was for, what broke, or
what anyone concluded. A digest built over a store that holds prose reads like a briefing; this one
reads like a table of contents.

**Which is both the reason to inject it and the reason it is off by default.** A table of contents is
worth its tokens where the reader can act on it, and here the agent can: it has a read of its own, and
a date, an actor or a reference is enough to follow. What the digest buys is the difference between a
session that opens knowing nothing and one that opens knowing *what exists and what is worth asking
about* — the cheaper route to the same records. Where the records are all one shape — a store whose
every row is `answer/partial` — the same block reads as noise and costs exactly what signal costs.
Nobody but the operator can tell those two stores apart, so `--digest-days` stays unset until somebody
who has looked names a window.

```
harness-memory: no session-opening digest: set config.digestDays to the number of days of recent activity a session should wake up holding
harness-memory: injected a session-opening digest of 9 record(s) over the last 14 day(s)
harness-memory: no session-opening digest, and recall is unaffected: …
```

The middle line is at info and appears at most once per session. A log showing it on consecutive turns
of one conversation is the fence broken, which is the first thing to check and the thing the mutants
exist to keep from shipping.

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

### The exec gate is emitted with its pre-approvals, or not at all

There is one more thing this gate cannot say on its own, and this one used to be emitted anyway.
Where agents run through the Claude CLI backend, that backend decides whether the model may use its
native tools *at all* by reading the gate as `security == "full" && ask == "off"`. Anything else is
not a narrower permission, it is a refusal of each native tool call, without ever consulting the
allowlist:

```
OpenClaw exec policy denied Claude native tool use (security=allowlist, ask=on-miss)
```

So `{"security": "allowlist", "ask": "on-miss"}` on such a host is not a stricter deployment, it is a
stopped one — and nothing about it looks stopped. Recall still runs at `before_prompt_build`, so the
agent still answers, out of memory, and writes nothing. `openclaw config patch --dry-run` passes.
`openclaw exec-policy show` renders the dead policy as a tidy table. This generator used to emit that
block with nothing beside it, and the deployment that turned the gate on found out by measuring.

What makes the strict gate survivable is pinning the backend's own argv:
`agents.defaults.cliBackends.claude-cli.args` carrying `--allowedTools` with the commands the agents
need. A pre-approved command raises no permission request, so it never reaches the refusal. The two
are therefore emitted together or neither is emitted, and `--backend-arg`s with no `--allowedTools`
among them are refused outright rather than paired with a gate they cannot survive — that pairing is
the bricked config spelled out, and it is the one input for which quietly succeeding would be
indistinguishable from working.

Which commands to pre-approve is not the policy's to know. The policy grants no programs, so an
allowlist generated from it would be empty, which is the same outage by another road. Hence the
default: no gate, the deployment's existing exec posture left alone, layer 2 doing the enforcing. A
generator that emits less is a smaller thing to read than one whose output cannot be applied without
disarming the agents.

Read that together with *[The hook sees the harness's own tools, not the
model's](#the-hook-sees-the-harnesss-own-tools-not-the-models)* and the shape of the gap is clear. On
a `claude` backend, `ask: on-miss` never reaches a person: the pinning is the whole of what may run,
and anything it does not name is refused where the request would have been raised. Layer 2 is not
called for the shell at all. So the shell there is gated by a list of pre-approved commands and by
nothing at all that reads the policy — which is what installing the `claude-code` harness beside this
one is for. On a host whose agents work through this harness's own `exec` tool, both layers apply as
written.

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
