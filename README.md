# agent-harness

A modular multi-agent orchestrator: one agent interface, portable adapters, and a dispatcher that
owns the things individual agents should not.

## The shape

```
   adapters/            crates/harness-dispatch        crates/harness-agent
   ┌──────────┐         ┌────────────────────┐         ┌──────────────────┐
   │ cli      │         │ normalise + dedupe │         │  trait Agent     │
   │ webhook  │ ──────▶ │ route by capability │ ──────▶ │  handle(task,ctx)│
   │ chat     │         │ load context        │ ◀────── │  → Outcome       │
   └──────────┘         │ deliver egress      │         └──────────────────┘
    portable, own       └────────────────────┘                  │
    language, own                  │                            │ records
    lifecycle                      └──── memory (yaam) ─────────┘
```

Three boundaries do the work:

**Adapters are separate and portable.** An adapter turns whatever a source speaks into an
`Envelope`, and delivers an `Egress` back. It is not linked into the core, does not have to be
Rust, and can be deployed and restarted on its own. Adding a source means adding a directory under
`adapters/`, not touching the dispatcher.

**Agents implement one trait.** An agent receives a `Task` and a `Context` and returns an
`Outcome`. It does not reach for a channel, a database, or a clock of its own — everything arrives
through `Context`, which is what makes an agent testable with no infrastructure at all.

**The dispatcher owns delivery.** Agents return the messages they want sent; the dispatcher sends
them. That indirection is the only reason an egress filter can be relied on: an agent that could
post directly could bypass it.

**One tool policy, two enforcement points.** `spec/tool-policy.json` says which reads, writes,
commands and hosts are refused. A harness's own allow/deny config is generated from it, and
`harness-guard` enforces the same file as a pre-tool-use hook — a process that exits non-zero, with
no model in the loop and no assumption that the generated config was ever installed.

A secret is recognised by what a file is called, and only incidentally by where it sits. A pattern
naming a directory (`**/secrets/**`) is a convention the deployment owns — its key store is free to
be called something else — and a pattern naming an extension matches only the last component, so a
keyring called `keyring.json` and a `key.pem.bak` beside it both fall through one. Key material
therefore carries a rule keyed on the role word in the filename, which survives the directory being
renamed and is narrow enough that a rotation log next to the keys stays readable.

A role word on its own is not enough, and the first version of that rule proved it by refusing
`keystore.rs` and `grep -rn passphrase .` — the guard resolves every argument of a command as a path,
so a bare search term is a filename in the working directory. What the role word has to arrive with
is a **data extension**: `keyring.json` and `key.passphrase` are the store and what unwraps it, while
`keystore.rs`, `keystore.md` and a bare `passphrase` are things written *about* one. So the patterns
name the serialisation formats rather than excusing the source ones — that keeps a language nobody
has written in this repository yet readable, where a `.rs` exception would need extending for each
new one. The narrowing is paid for at the other end, and stated here so it is a choice: a key store
in a file called exactly `keyring`, with no extension, is not matched, because that string is also
what a person greps for.

The cost of that narrowness is stated rather than left to be discovered: a rule that names files does
not refuse a recursive read *of the directory holding them*, because the command names no file the
patterns can see. `grep -r . <key store>` is allowed where `grep -r . ~/.ssh` is not, and the same is
true of `~/.aws/credentials` and `~/.kube/config`. That is layer 4's ground (§10.2), and it is
asserted in the test suite so that closing it by denying the tree is a decision somebody makes on
purpose rather than a tightening that quietly takes the readable files with it.

### What a command line can still hide

A path rule can only fire on a path the command parser found, so the parser's reach *is* the rule's
reach. It finds a value assigned inside a token — `ROOT=<store> app` and `--root=<store>` alike,
which hand a program a path that is never an argument — and `$'…'` no longer leaves a `$` glued to
the front of a filename. Redirections in both directions, `$(…)`, backticks, process substitution,
quoting, escaping and the wrapper list were already covered, and every one of those shapes is
asserted rather than assumed.

**A wrapper's flag operand is a candidate too**, which it was not until measured. The same program
search that skips a run of flags then takes the next token as the program — so a wrapper flag
spending that token on a *separated* operand hands the path to the search rather than to the rules.
`xargs -a <store> cat` was admitted where `cat <store>` was refused, and so was every wrapper flag
of that shape: `env -C`, `sudo -D`, `sudo --chroot`, `doas -C`, `time -o`. Only the separated
spelling was open; `-a<store>` and `--arg-file=<store>` were already recovered as values inside a
token, which is why it went unseen. Every wrapper flag is now read as though its operand were a
path, rather than the ones anybody can list: which flags take one is not something a command line
says, a deployment's `sudo` is not the one this was written against, and a flag added next year is
spelled nothing yet. The cost, stated: a flag whose operand is a *word* offers that word to the path
rules, where it resolves to a name in the working directory — which is what an ordinary argument
already does, and why nothing in this policy matches a bare word.

**A program handed to an interpreter is refused rather than read.** `sh -c '<line>'`,
`python3 -c '<program>'` and `perl -e '…'` put the whole call inside one opaque word, so no rule in
this policy could see any of it and every one of them was admitted. The alternative was to recurse —
read that word as another command line — and that means ruling on which programs take a command
*line* and which take a *program*. The two are not the same language: `python3 -c 'open(p)'` names a
path no shell parser would find, so reading a program as a command line gets the answer wrong in the
permissive direction, which is the one direction this guard does not err in. The shape is therefore
refused and nothing at all is claimed about its contents — in every spelling, including a clustered
flag (`-lc`), a value attached to it (`-c…`), a long form, a program arriving on standard input, and
an interpreter reached through a wrapper or through `find -exec`. The surface is declared in
`spec/tool-policy.json`; a policy document written before the rule gets the built-in list rather than
an empty one, because a rule that can be *declared* and not *had* is the failure this one was built
from.

**Through a wrapper includes the wrapper's own operand**, which it did not at first. The program
search skips a run of flags and assignments and takes the next token, so a wrapper that spends that
position on a separated operand — `timeout 5`, `nice -n 5` — leaves the interpreter behind it among
the arguments. `timeout 5 sh -c …` still refused there, on the `-c`; `timeout 5 sh` did not, because
the program arrives on standard input and no token names it, so the empty tail read as a mention.
What decides it now is that a wrapper was walked at all: once one has been, the parse has settled on
a token it cannot tell from an operand, and the tokens between it and the interpreter are unread
either way. So behind a wrapper an interpreter that **ends the line** is refused wherever it sits,
which covers a second operand (`timeout -k 1 5 sh`) and a second wrapper (`sudo timeout 5 sh`)
without counting either. Counting a wrapper's operands would be the narrower answer and it is not
available: a parse that could count them would not have had the gap.

It is drawn narrowly on purpose. An interpreter handed a **script file** is not refused: the file is
at a path the path rules already read, it got there through a write gate of its own, and a `#!` line
runs it as `./script` with no interpreter in the command at all — so refusing that spelling would buy
no property while breaking every installer here. Inline eval has no second spelling, which is exactly
why it is the shape that is refused. `timeout 5 sh install.sh` is admitted for the same reason
`sh install.sh` is, and a bare mention stays a mention: `which bash` and `ls -la /bin/sh` run
nothing and are not refused.

What that last closure costs, stated rather than left to be found: behind a wrapper the mention is
refused too. `timeout 5 which bash` and `timeout 5 ls /bin/sh` name an interpreter at the end of a
line whose program position is already unreadable, and telling them from `timeout 5 sh` means knowing
which of the earlier tokens were operands. The cheaper reading is the permissive one, and it is the
one this guard does not take — the same trade already made for `echo sh -c`.

Four things this does **not** cover, named here rather than left to be found. They are not a
complete list, and nothing here could be: this is a string comparison over a command line, and the
shell has not run yet.

- **Anything a shell would expand.** `$HOME/…`, `${VAR}/…`, `*` and `{a,b}` name paths this parser
  cannot know, because the expansion happens in a shell that has not started.
- **A `cd` earlier in the same line.** A relative candidate resolves against the working directory
  the guard was handed, so `cd <parent> && cat <name>` reaches a rule anchored to an absolute prefix
  that `cat <parent>/<name>` would not. It is the same answer for an argument, a redirection and an
  assignment.
- **A *program* behind a wrapper's operand, when the rule names the program.** The paragraph above
  makes a wrapper's operand a candidate *path*; it does not make what follows the operand a
  candidate *program*. The search still settles on the operand, so `timeout 5 rm -rf /` and
  `sudo -u root nc -l 1234` are read as programs called `5` and `root` with `rm` and `nc` among
  their arguments — measured admitted, where `rm -rf /` and `sudo nc -l 1234` are refused. The
  inline-program gate is unaffected, because it reads the whole tail rather than the program
  position (`timeout 5 sh` is refused). Closing this for the command, writing and egress rules means
  either counting a wrapper's operands, which this parse cannot do, or promoting every token behind
  a wrapper to a program name, which refuses `timeout 30 cargo build --bin ssh`. It is a trade
  nobody has made yet rather than an oversight, and it is written down here so that it is one.
- **An interpreter nobody listed.** The interpreter surface is a list, and a list is what somebody
  thought of. `awk`, `sed` and `jq` are off it deliberately — their program *is* their first operand,
  so refusing "an inline program" for them refuses the tool outright, and their input arrives as
  ordinary path arguments the path rules already read. What that leaves open is a program naming a
  path inside itself, as `awk 'BEGIN{getline < "<store>"}'` does.

These are layer 4's ground (§10.2), for the same reason the recursive read above is: they are where a
string comparison over a command line stops being able to see what the command will do. A deployment
that needs them closed needs confinement, not a longer parser.

## Why an agent does not post its own replies

It is the difference between a rule and a habit. If every agent can reach the channel, "redact
before sending" is a convention that holds until someone forgets. If only the dispatcher can, it is
a property of the system.

## The egress screen

Because delivery is in one place, the redaction pass can be too. `harness-screen` runs over the
**rendered** message — the finished bytes, after every filter, immediately before the adapter takes
it. That position is the point: a secret gets into an outbound message by being interpolated into
one, so a check on the agent's fields or on the template runs before the value exists and passes.

It masks and reports, rather than masking quietly. Every match comes back to the caller as part of
the dispatch — which rule, which policy, where in the message, and which delivery it was going out
on — because a send path that edits a message silently leaves the caller believing it sent what it
wrote, and nobody learns that a credential needs rotating.

The pattern set is data: `spec/egress-screen.toml`, compiled in as the shipped default so the screen
is on before anything is configured, and replaceable per deployment with `egress_policy` in
`config.toml`. A policy named there that cannot be read stops the process rather than falling back.

## Layout

```
crates/
  harness-agent      the Agent trait, Task, Outcome, Context — what an agent codes against
  harness-envelope   source-neutral inbound message and outbound egress
  harness-dispatch   normalise, route, guard, deliver; the route decision and the worker
  harness-memory     client for the memory service; bundles in, records out
  harness-screen     the egress screen: credential shapes out of a rendered message
  harness-cli        run a dispatcher, or run a single agent for development
  harness-policy     the tool policy, the guard that enforces it, one generator per harness
  harness-sandbox    confinement: workspace permissions, sandbox artefacts, per-agent keys
adapters/            one directory per source. Portable, independently deployable.
harnesses/           glue for adopting the policy in one harness. No rules live here.
spec/                policies that are configuration rather than code, not hardcoded rules
setup/               install script and a setup skill
```

## Quick start

```sh
setup/install.sh --adapter cli --harness claude-code
harness run --agent echo

# the guard, without a model in the loop
echo '{"tool":"read","intents":[{"kind":"read","value":"~/.ssh/id_rsa"}]}' | harness-guard check
echo $?   # 2 — blocked by the private-keys rule
```

Confinement is a separate, deliberate step, because it touches key material and permissions:

```sh
setup/provision.sh --agent research --agent triage
```

## One sandbox, described once

A deployment runs a systemd unit and a lab runs a container. Written separately they drift, and then
what the lab exercises is the lab's own sandbox. So both are generated from one declared policy, and
a test reads each artefact *back* and fails if they stop agreeing on any hardening property. Details
in `crates/harness-sandbox`.

## License

MIT — see [LICENSE](LICENSE).
