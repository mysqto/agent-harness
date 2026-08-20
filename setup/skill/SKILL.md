---
name: harness-setup
description: Set up, configure, or add an adapter to an agent-harness deployment. Use when someone wants to install the harness, connect a new message source, register an agent, or diagnose why messages are not arriving.
---

# Setting up agent-harness

## Deciding what is being asked

Three requests look similar and need different work:

| Request | What it means |
|---|---|
| "install the harness" | Build binaries, write a config — `setup/install.sh` |
| "connect X" | Add an adapter for source X — usually a new directory under `adapters/` |
| "add an agent" | Implement the `Agent` trait and register it |

## Installing

```sh
setup/install.sh --adapter cli
```

Re-runnable. It will not overwrite an existing config, so a second run after editing config is safe.

Check it worked without standing anything up:

```sh
echo 'summarise order ord-91h2' | harness-adapter-cli
```

With no ingress socket the adapter prints the envelope it *would* have sent. That is the fastest way
to see whether the contract is satisfied.

## Connecting a new source

Copy `adapters/cli` — it is the smallest thing satisfying the contract, so your diff is only what
the source actually needs. Read `adapters/README.md` for the two message shapes.

Three mistakes account for most adapter bugs:

1. **Minting `envelope_id` per attempt.** Sources retry. Derive the id from the source's own
   identifier for the message, or deduplication has nothing to match and one message becomes several
   tasks.
2. **Composing replies in the adapter.** Outbound text passes an egress filter before an adapter
   sees it. An adapter that writes its own messages routes around that filter.
3. **Returning a final-looking error when ingress is down.** Answer so the source retries — `503`
   rather than `500` for HTTP — since the retry carries the same id and costs nothing.

## Adding an agent

Implement `Agent` from `harness-agent`: `id`, `capabilities`, `handle`. Everything the agent needs
arrives through `Context`, so a unit test needs no infrastructure — construct a fake `Context` and
call `handle` directly.

Declare `mutating: true` on any capability that changes state somewhere. The dispatcher uses it to
refuse acting on incomplete context, and it can only do that if the declaration is honest.

## When messages are not arriving

Work along the path, in this order — it is roughly cheapest-to-check first:

1. Does the adapter emit anything? Run it with no socket; it prints envelopes.
2. Does the socket exist and is it writable? `ingress_socket` in the config.
3. Is the dispatcher routing? An intent no agent declares is `Unroutable`, and an intent two agents
   declare is `Ambiguous` — deliberately an error, because picking one would make behaviour depend on
   registration order.
4. Was it a duplicate? A repeated `envelope_id` is dropped by design. If real messages are vanishing,
   suspect an adapter deriving ids too coarsely.
5. Was it refused? A mutating task on degraded context is refused before the agent runs. The refusal
   names the intent and what the context was missing, so it says which source was unreachable rather
   than only that one was.
