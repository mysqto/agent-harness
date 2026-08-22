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
  harness-dispatch   normalise, route, guard, deliver
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
