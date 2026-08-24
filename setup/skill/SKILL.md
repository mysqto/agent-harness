---
name: harness-setup
description: Set up, configure, confine, or add an adapter to an agent-harness deployment. Use when someone wants to install the harness, connect a new message source, register an agent, wire the tool policy into a harness, provision per-agent workspaces and signing keys, rotate a key, generate the sandbox artefacts, or diagnose why messages are not arriving or why a tool call was refused.
---

# Setting up agent-harness

## Deciding what is being asked

Four requests look similar and need different work:

| Request | What it means |
|---|---|
| "install the harness" | Build binaries, write a config — `setup/install.sh` |
| "connect X" | Add an adapter for source X — usually a new directory under `adapters/` |
| "add an agent" | Implement the `Agent` trait and register it |
| "lock down the tools" | Wire the tool policy into a harness — `--harness`, below |
| "why was that refused?" | Ask the guard directly; it answers without a model in the loop |
| "confine it" | Provision workspaces, keys and sandbox artefacts — `setup/provision.sh` |

## Installing

```sh
setup/install.sh --adapter cli --harness claude-code
```

Re-runnable. It will not overwrite an existing config, so a second run after editing config is safe.

Check it worked without standing anything up:

```sh
echo 'summarise order ord-91h2' | harness-adapter-cli
```

With no ingress socket the adapter prints the envelope it *would* have sent. That is the fastest way
to see whether the contract is satisfied.

## Wiring the tool policy

Two layers, one set of rules in `spec/tool-policy.json`:

1. the harness's own allow/deny config, **generated** from that file, and
2. `harness-guard`, a pre-tool-use hook that exits 2 to block.

`setup/install.sh --harness claude-code` installs the guard, copies the policy somewhere editable,
and runs `harnesses/claude-code/install.sh` to write both. It will not overwrite an existing settings
file — it writes the generated config beside it and prints the merge.

Prove it refuses something before believing it:

```sh
echo '{"tool":"read","intents":[{"kind":"read","value":"~/.ssh/id_rsa"}]}' | harness-guard check
echo $?    # 2
```

Exit 0 allowed, 2 blocked. There is no code for "could not decide" — a bad payload or an unloadable
policy is a block.

`--harness hermes` wires the other harness this repo ships. It has no deny list to generate, so the
hook carries every rule, and it reads its verdict from the hook's **stdout** rather than the exit
code — `harnesses/hermes/README.md` covers both, and the ways its own hook-consent gate can leave the
hook installed and enforcing nothing.

**Adopting another harness** is a translator (`crates/harness-policy/src/harness/<name>.rs`) plus an
installer (`harnesses/<name>/install.sh`); `harnesses/README.md` has the contract. A harness that can
emit the neutral tool-call shape needs neither: point its hook at `harness-guard check` as it is.

**When the guard blocks something it should not**, ask it and read the rule name it reports, then edit
the policy — not the generated config, which is output and will be regenerated. Re-run the harness
installer afterwards so layer 1 matches. Note what the hook enforces that a settings file cannot:
writes are confined to the workspace, and egress goes only to allowlisted hosts.
## Confining a deployment

Installing binaries and confining them are separate steps on purpose: the second touches key
material and permissions, so it is run where the deployment lives rather than on a laptop.

```sh
setup/provision.sh --agent research --agent triage
setup/provision.sh --audit             # permissions still at least as tight as the policy
setup/provision.sh --rotate research   # new key; the old one stays valid for 24h
```

Provisioning creates, per agent, a private workspace at `0700`, a segregated
`memory/private/<agent>/` at `0700`, and one signing key at `0600` — and it never replaces a key an
agent is already signing with, because that would invalidate everything in flight. Re-running it is
safe and reports only what changed.

### One sandbox, two artefacts

`provision` writes both a systemd unit and a container profile from **one** declared policy
(`sandbox/policy.json`). That is not tidiness: a lab that exercises a hand-written container
profile proves the lab's sandbox, not the deployed one. The tool refuses to write the pair unless it
can read both back and find them agreeing on every hardening property, `check` re-runs that against
the files on disk, and a test in `crates/harness-sandbox` asserts it for every property in the
policy.

To open one egress destination without editing the shared policy:

```sh
setup/provision.sh --agent research --allow 10.0.0.0/8
```

Everything unlisted is denied — in the unit via `IPAddressDeny=any`, in the container via the
network the profile names. The two mechanisms differ; the policy they carry does not.

### Two things worth not confusing

1. **A signature proves origin, not permission.** Verifying a request tells you which agent sent it.
   Whether that agent may do what it asked is the role check, with its own inputs. Key possession is
   not authorisation, and nothing here lets a caller pass one where the other is expected.
2. **`private/` has no operator override.** It exists so a reader holding the operator role but not
   the identity cannot open those records. If an operator genuinely needs them, that is a change of
   identity, and it should be as visible as one.

Key rotation has its own runbook: `knowledge/runbooks/memory-key-rotation.md`.

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

A tool call refused inside the harness is a different failure with a different answer: that is the
guard, it names the policy rule it applied, and `harness-guard check` reproduces it on demand.
