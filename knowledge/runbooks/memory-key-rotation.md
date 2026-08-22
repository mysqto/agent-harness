# Runbook: rotating an agent's signing key

A signing key proves **origin**: a record signed with the key of `research` came from `research`.
It grants nothing — what that agent may read, write or erase is the role check, a separate decision.
So a rotation changes who can *prove* they are an agent, and never changes what that agent may do.

## When

- **Quarterly**, as routine.
- **Immediately**, on any suspected exposure: a key file found readable beyond its owner, a key in a
  log, a backup or a chat message, a host with unexplained access, a departing operator who held one.

`harness-sandbox audit` reports a key file whose mode is wider than `0600`. Treat every hit as an
exposure — the file was readable, and nothing logs who read it.

## Rotate

```sh
setup/provision.sh --rotate research
```

That replaces the current key and keeps the previous one acceptable for **24 hours**. The overlap is
the point: requests already in flight, spooled by a sidecar, or being retried were signed with the
old key, and a hard cutover fails all of them at the moment somebody is rotating because they think
something leaked.

Then:

1. Distribute the new key to the agent's own host and nowhere else. One key per agent, one file
   per key — a key shared between two agents makes every record either of them writes unattributable.
2. Restart the agent so it picks the new key up.
3. Before the window closes, confirm nothing is still signing with the old one. A verification that
   matched the retired key is worth logging for exactly this reason, and it names the agent.

## After the window

The retired key stops being accepted 24 hours after the rotation, to the millisecond. Nothing
sweeps it: a request signed with it is refused, with a message that says the overlap ended rather
than that the signature was wrong — a caller to chase, not an attacker.

## What a rotation does not do

- **It does not revoke access.** A rotated-out key holder loses the ability to prove identity; a
  role that was too broad is still too broad. Fix the role separately.
- **It does not re-sign history.** Records already written keep the signature they were written
  with; the audit trail is about who wrote a record then, not about which key is current now.
- **It does not erase anything.** If the exposure means data has to go, that is erasure, and
  erasure is operator-only and has its own runbook.
