# Adapters

An adapter connects one source to the orchestrator. It is a **separate process in whatever language
suits the source** — not a plugin, not a linked crate. Adding a source means adding a directory
here; it does not mean touching the dispatcher.

## The contract

An adapter does exactly two things.

**Inbound.** Turn a source event into an `Envelope` and write it as one line of JSON to the
dispatcher's ingress socket.

```json
{"envelope_id":"cli-1755612000-4a2f","source":"cli","received_at":"2026-08-19T14:30:12Z",
 "attempt":1,"reply_to":"stdout","actor":"local","body":"summarise order ord-91h2","extra":{}}
```

**Outbound.** Read `Delivery` lines and send them wherever the source expects.

```json
{"envelope_id":"cli-1755612000-4a2f","target":"stdout","text":"3 events in the last day.","thread":null}
```

That is the whole interface. No SDK, no version coupling — a shell script with `jq` is a legitimate
adapter, and `adapters/cli` is exactly that.

## Rules that matter

**`envelope_id` must be derived from the source's own identifier for the message, not minted per
attempt.** Sources retry. An adapter that generates a fresh id each time turns one message into
several tasks, and the dispatcher's deduplication cannot save you because it has nothing to match on.

**Stamp `received_at` on receipt, not on send.** It records when the source handed it over.

**Report `attempt` when the source provides it.** A value above 1 is the signal that deduplication is
about to be load-bearing.

**Never deliver a message the dispatcher did not hand you.** Outbound text passes an egress filter
before it reaches an adapter. An adapter that composes its own replies routes around that filter,
which is precisely the property the split exists to protect.

## Contents

| Adapter | Language | Use |
|---|---|---|
| `cli/` | POSIX shell | Development and scripting. Reads stdin, writes stdout. |
| `webhook/` | Python 3 | Receives HTTP POSTs; replies are sent back to a configured URL. |

## Writing a new one

Copy `cli/`. It is deliberately the smallest thing that satisfies the contract, so the diff between
it and your adapter is only what your source actually requires.
