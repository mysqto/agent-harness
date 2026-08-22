# Claude Code

Wires `policy/tool-policy.json` into a settings file: the deny list is layer 1, the `PreToolUse` hook
is layer 2.

## Install

```sh
setup/install.sh --harness claude-code            # builds, installs the guard, wires this harness
harnesses/claude-code/install.sh --scope user      # or wire it by hand, for ~/.claude
```

The installer never overwrites an existing settings file. If one is there, it writes
`settings.harness-policy.json` beside it and prints the merge, so a hand-edited settings file is
never silently replaced.

## What is generated

```json
{
  "permissions": {
    "deny": ["Read(~/.ssh/**)", "Write(~/.bashrc)", "Bash(passwd:*)", "…"],
    "allow": ["WebFetch(domain:127.0.0.1)"]
  },
  "hooks": {
    "PreToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "harness-guard check --harness claude-code --policy …" }] }]
  }
}
```

Regenerate at any time — the policy is the source, this file is output:

```sh
harness-guard emit --harness claude-code
```

## What layer 1 here cannot say

Two rules are enforced **only** by the hook, because a deny list cannot express "everything except":

- **Writes are confined to the workspace.** A settings deny list would need to enumerate the whole
  filesystem to say it.
- **Egress goes to allowlisted hosts only.** The generated `allow` entries stop the permitted hosts
  being prompted for; they cannot deny the rest.

Command denies are also coarser than the hook. `Bash(passwd:*)` is a prefix match, while the hook
splits the command line on every shell operator, sees through `sudo`, `env` and `xargs`, recovers
redirection targets as writes, and checks each argument against the secret paths. So
`ls && sudo rm -rf ~` is one refusal to the hook and invisible to a prefix match.

This is why layer 2 exists, and why it never asks whether layer 1 ran.

## Checking the wiring

```sh
echo '{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}' \
  | harness-guard check --harness claude-code; echo "exit $?"
```

Expect `exit 2` and a refusal naming the `private-keys` rule on stderr. If you get `exit 0`, the
guard is reading a different policy than you think — pass `--policy` explicitly and try again.
