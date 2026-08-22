# Invariants

Anything landing in this repo must hold these. CI enforces what can be mechanically enforced; the
rest is on review.

## 1. Generic by construction

This repo is domain-neutral and must stay that way. It carries **no** organisation names, employer
names, internal hostnames, team names, ticket prefixes, chat channel or user IDs, colleague names, or
domain vocabulary borrowed from any specific company's systems.

Entity kinds, attribute keys and redaction policies are **configuration** (`spec/`), never hardcoded
domain terms. Examples in docs and tests use neutral vocabulary: `order_ref`, `ticket`,
`pull_request`, `deploy`, `chat_user`. CI fails the build on a denylist of leaked terms.

## 2. The index is derived, always

Nothing may be indexed that is not present in the Markdown tree (or a local cold manifest). Every
column must be reproducible by `yaam reindex`. This is what makes the store portable, and it is easy
to break silently — a round-trip test guards it.

## 3. No claimed guarantee without a mechanism

A filesystem rename cannot join a SQLite transaction. Do not write "atomic" where the mechanism
delivers *recoverability*. Every partial failure needs a defined winner and a sweeper that converges.

## 4. Crypto invariants are types, not comments

- A nonce is constructible only from a CSPRNG; re-sealing takes a fresh key *and* nonce.
- Associated data is recomputed from record identity, never read from the stored blob.
- A record's key is derived from *all* subject shares, so an any-one-suffices misbuild cannot decrypt.
- Changing a record's subject set re-encrypts under a fresh key. Never re-wrap the old one.

## 5. Idempotency is per-hop

Every write path is keyed and safe to replay: unique record ids, compound keys on fan-out targets,
recomputed counters rather than incremented ones.

## 6. A rule is written once, enforced twice

`policy/tool-policy.json` is the only place a tool rule is declared. A harness's own allow/deny
config is generated from it; the guard evaluates the same file at the tool-call boundary. Neither
layer may assume the other ran, and a generator may omit a rule its harness cannot express but must
never emit an allow the policy does not grant.

Fail closed: an unparseable payload, an unloadable policy and a rule violation are the same answer.
There is no exit code meaning "could not decide".

## 7. Tests and docs are part of the change

- Line coverage ≥ 85%, enforced in CI, and **blocking** since `harness-dispatch` landed (97.85% at
  the time of writing). The `todo!()` bodies still to come drag the figure down without excusing it:
  a crate that cannot reach the gate is a crate whose tests have not been written yet.
- `cargo clippy --all-targets -- -D warnings` clean.
- Every public item documented. Comments explain *why*, briefly — no restating the code.

## Running the gates

```sh
ci/check.sh      # hygiene, fmt, clippy, tests, coverage — the same set CI runs
```

CI runs the same set on every push and pull request (`.github/workflows/ci.yml`). Keep the two in
lockstep: a gate that exists only in CI is discovered late, and one that exists only locally is
bypassed.
