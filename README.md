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

## Why an agent does not post its own replies

It is the difference between a rule and a habit. If every agent can reach the channel, "redact
before sending" is a convention that holds until someone forgets. If only the dispatcher can, it is
a property of the system.

## Layout

```
crates/
  harness-agent      the Agent trait, Task, Outcome, Context — what an agent codes against
  harness-envelope   source-neutral inbound message and outbound egress
  harness-dispatch   normalise, route, guard, deliver
  harness-memory     client for the memory service; bundles in, records out
  harness-cli        run a dispatcher, or run a single agent for development
  harness-sandbox    confinement: workspace permissions, sandbox artefacts, per-agent keys
adapters/            one directory per source. Portable, independently deployable.
setup/               install script and a setup skill
```

## Quick start

```sh
setup/install.sh --adapter cli
harness run --agent echo
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
