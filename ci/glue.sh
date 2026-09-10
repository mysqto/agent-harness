#!/usr/bin/env bash
# Tests the shell that installs the tool policy. The guard's own rules are covered by cargo tests;
# this covers the part cargo cannot see — that the installers parse, write what the harness reads,
# and wire a hook that actually refuses something.
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
note() { echo "  $*"; }
fail() { echo "::error::$*"; status=1; }

echo "→ shell parses"
while IFS= read -r script; do
  bash -n "$script" || fail "$script does not parse"
done < <(find setup adapters harnesses -name '*.sh' -type f | sort)

echo "→ every harness has an executable installer"
for dir in harnesses/*/; do
  [ -d "$dir" ] || continue
  [ -x "$dir/install.sh" ] || fail "$dir has no executable install.sh"
done

echo "→ building the guard"
cargo build --quiet -p harness-policy --bin harness-guard
guard="$PWD/target/debug/harness-guard"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

## Key material ################################################################
# Every pattern in the secret list that is not a literal path is a convention: an extension, or the
# name of a directory. A deployment's key store is free to satisfy neither -- it holds a signing
# keyring called `keyring.json` and the passphrase that unwraps it, in a directory the deployment
# named itself -- and for a while it did, with only its `*.key` neighbours refused. So the claim
# checked here is that a key store this policy has never heard of is refused on the strength of what
# its files are called, in a directory named nothing the policy could predict. The mutants matter
# more than usual: with the extension pattern left in place, the section below passes just as
# happily against the policy that shipped the hole.
#
# The other half is here for the same reason. A role word matched anywhere in a filename refused
# `keystore.rs` and a bare `grep -rn passphrase .`, because the guard resolves every argument of a
# command as a path: the rule meant to gate the agent that reviews key handling was what stopped it
# reading key handling. So the role word arrives with a data extension or it carries nothing, and
# both directions are asserted below with a mutant behind each.

echo "→ a key store the policy has never heard of is refused by what its files are called"
policy="$PWD/spec/tool-policy.json"
keys="$work/whatever-this-deployment-called-it"
mkdir -p "$keys" "$work/keyhome" "$work/keywork"
for name in keyring.json key.passphrase keyring.json.bak unseal.key subject.key \
            README.md rotation-log.txt \
            keystore.rs keyring.rs subject.rs custody.rs wrapper.rs passphrase-rotation.md; do
  printf 'x\n' > "$keys/$name"
done

# Exit code only: what a person reads on a refusal is asserted by the cargo tests, which can name
# the rule that fired. What cannot be checked there is a real directory on a real filesystem, where
# the guard canonicalises before it matches.
keyread() {
  local file="$1" policy="$2" code
  set +e
  printf '{"tool":"read","intents":[{"kind":"read","value":"%s"}]}' "$keys/$file" \
    | env HOME="$work/keyhome" HARNESS_WORKSPACE="$work/keywork" \
      "$guard" check --policy "$policy" >/dev/null 2>&1
  code=$?
  set -e
  echo "$code"
}

# The same, for a command line, run *from inside* the key store. The guard resolves every argument of
# a command as a path against the working directory, so a bare search term is the worst case for a
# rule that matches on a name: `passphrase` becomes `<key store>/passphrase`, and no cargo test can
# stand in for a real cwd on a real filesystem.
keycmd() {
  local line="$1" policy="$2" code
  set +e
  (
    cd "$keys" || exit 3
    printf '{"tool":"bash","intents":[{"kind":"command","value":"%s"}]}' "$line" \
      | env HOME="$work/keyhome" HARNESS_WORKSPACE="$work/keywork" \
        "$guard" check --policy "$policy" >/dev/null 2>&1
  )
  code=$?
  set -e
  echo "$code"
}
for secret in keyring.json key.passphrase keyring.json.bak unseal.key subject.key; do
  [ "$(keyread "$secret" "$policy")" = 2 ] || fail "$secret was readable"
done
note "the keyring, its backup, the passphrase that wraps it and two keys are all refused"

echo "→ and what holds no key beside them is still readable"
# Refusing the whole tree is the easy answer and it hides the question. A note and a rotation log
# next to a key store are ordinary reads, and an agent asked why a key was rotated needs them.
for ordinary in README.md rotation-log.txt; do
  [ "$(keyread "$ordinary" "$policy")" = 0 ] || fail "$ordinary beside a key store was refused"
done

echo "→ and so is source and prose named for key material, wherever it sits"
# Measured on a real repository while this group was live: `crates/yaam-crypto/src/keystore.rs` and
# `crates/yaam-cli/src/keyring.rs` were both refused, in a tree with no key material in it at all.
# These sit in the key store itself, which is the hardest place for the rule to tell them apart.
for source in keystore.rs keyring.rs subject.rs custody.rs wrapper.rs passphrase-rotation.md; do
  [ "$(keyread "$source" "$policy")" = 0 ] || fail "$source was refused, and it holds no key"
done
note "a keystore and a keyring in source, their neighbours, and a note about passphrases all read"

# And the search that finds them. Refusing this is the same fault seen from the other side: the term
# is not a file, and a reviewer who cannot grep for a role word cannot review key handling.
for line in "grep -rn passphrase ." "grep -rn keystore ." "grep -rln keyring ."; do
  [ "$(keycmd "$line" "$policy")" = 0 ] || fail "\`$line\` was refused from inside a key store"
done
note "grepping a key store for the words its files are named after is allowed"

echo "→ both of those claims can fail: break each on a copy of the policy and the answer flips"
# Each mutant edits one line of a copy of the policy and requires one of the reads above to give the
# other answer. A mutant that changes the document but not the verdict means the assertion it was
# aimed at rests on something else, which is how a policy ships a hole with a green run over it.
mutant_dir="$work/policy-mutants"
mkdir -p "$mutant_dir"
policy_mutant() {
  local name="$1" change="$2" probe="$3" flips_to="$4" out="$mutant_dir/$name.json" built got
  set +e
  python3 - "$policy" "$out" "$change" <<'PY'
import json, sys

source, out, change = sys.argv[1], sys.argv[2], sys.argv[3]
policy = json.load(open(source))
before = json.dumps(policy, sort_keys=True)
verb, _, what = change.partition(":")
if verb == "drop-group":
    policy["secret_paths"] = [r for r in policy["secret_paths"] if r["id"] != what]
elif verb == "drop-pattern":
    for rule in policy["secret_paths"]:
        rule["patterns"] = [p for p in rule["patterns"] if p != what]
elif verb == "drop-interpreter":
    # An interpreter the gate no longer knows about. This is the state every guard shipped in
    # before this rule existed, and it is the shape that was measured admitted on a deployment.
    for entry in policy["inline_programs"]["interpreters"]:
        entry["programs"] = [p for p in entry["programs"] if p != what]
elif verb == "drop-wrapper":
    # The wrapper still there in the line but no longer one the parser walks. What decides the
    # empty-tail case is that a wrapper was walked at all, so this is the half of the claim the
    # interpreter list cannot carry.
    policy["command_wrappers"] = [w for w in policy["command_wrappers"] if w != what]
elif verb == "drop-command-program":
    # The program still named on the line but no longer named by any command rule. This is what
    # separates "the token behind the wrapper reached the program rules" from "the guard refuses
    # command lines": nothing else in the document refuses this line.
    for rule in policy["commands"]:
        rule["programs"] = [p for p in rule["programs"] if p != what]
elif verb == "drop-flag":
    # The interpreter still listed, but the token that hands it a program no longer recognised.
    for entry in policy["inline_programs"]["interpreters"]:
        entry["flags"] = entry["flags"].replace(what, "")
elif verb == "drop-sink":
    # The exemption gone, and nothing else touched. This is the state the policy shipped in, where
    # `/dev/**` answered for the null device the same way it answers for a disk.
    policy["redirect_sinks"] = [s for s in policy["redirect_sinks"] if s != what]
elif verb == "widen":
    # A group that gives up on naming what it protects and swallows a directory instead.
    group, _, pattern = what.partition("=")
    for rule in policy["secret_paths"]:
        if rule["id"] == group:
            rule["patterns"].append(pattern)
else:
    sys.exit(f"unknown mutation {verb!r}")
if json.dumps(policy, sort_keys=True) == before:
    sys.exit(f"{change!r} left the policy exactly as it was")
json.dump(policy, open(out, "w"))
PY
  built=$?
  set -e
  if [ "$built" -ne 0 ]; then
    fail "policy mutant $name changed nothing, so it proves nothing"
    return
  fi
  # A probe is a filename in the key store, or `cmd:` and a command line run from inside it.
  case "$probe" in
    cmd:*) got="$(keycmd "${probe#cmd:}" "$out")" ;;
    *)     got="$(keyread "$probe" "$out")" ;;
  esac
  if [ "$got" = "$flips_to" ]; then
    note "policy mutant $name was caught"
  else
    fail "policy mutant $name survived: $change did not change the verdict on $probe"
  fi
}
# The whole group gone. This is the state the policy shipped in, and `unseal.key` stayed refused
# throughout it -- which is exactly why the extension could not be left to speak for the directory.
policy_mutant key-material-dropped drop-group:key-material keyring.json 0
# One role word at a time, so a group that is present but no longer covers a file is caught too. The
# pattern each names is the role word paired with the data extension that makes it key material --
# dropping the pair is what a rename of the group's shape would do, and both files above depend on
# exactly one pattern each.
policy_mutant keyring-unmatched drop-pattern:'**/*keyring*.json*' keyring.json.bak 0
policy_mutant passphrase-unmatched drop-pattern:'**/*.passphrase' key.passphrase 0
# And the extension pattern that was doing all the work, so the older half of the claim is asserted
# rather than assumed to still hold.
policy_mutant extension-unmatched drop-pattern:'**/*.key' unseal.key 0
# The other direction, and the one this section exists to keep honest: a group that denies the
# directory it found key material in would pass every assertion above while taking the rotation log
# with it, and would be back to matching on a name the deployment owns.
policy_mutant denies-the-whole-tree widen:key-material='**/whatever-this-deployment-called-it/**' \
  rotation-log.txt 2
# And the regression this group actually shipped, which is the same mistake in a third direction: a
# role word matched anywhere in a filename with nothing paired to it. Re-add either of the two
# patterns that did it and the assertions above go green while a source file and a grep go dark, so
# each gets a mutant of its own rather than sharing one.
policy_mutant role-word-alone-refuses-source widen:key-material='**/*keystore*' keystore.rs 2
policy_mutant role-word-alone-refuses-a-search widen:key-material='**/*passphrase*' \
  cmd:'grep -rn passphrase .' 2

## A path that is never an argument ############################################
# A rule can only fire on a path the command parser found, and for a while it did not find one handed
# to a program *inside* a token. `ROOT=<store> app` was admitted where `app --root <store>` was
# refused, and so was `app --root=<store>`: the value never became a candidate, so no pattern could
# match it. Asserted here as well as in the cargo tests because a real deployment was measured this
# way -- a store refused by argument and admitted by environment is a gate that only reads as closed.
echo "→ a path reaching a program inside a token is a candidate, not decoration"
for line in "STORE_ROOT=$keys/keyring.json tool run" \
            "STORE_ROOT+=$keys/keyring.json tool run" \
            "env STORE_ROOT=$keys/keyring.json tool run" \
            "STORE_ROOT=$keys/keyring.json" \
            "tool --store=$keys/keyring.json run" \
            "tool -s$keys/keyring.json run"; do
  [ "$(keycmd "$line" "$policy")" = 2 ] \
    || fail "\`$line\` was admitted: the value inside the token never became a candidate path"
done
note "an environment prefix and an attached flag value are read like an argument"

# What that costs, on the same real filesystem: every `name=value` token now offers its value up. A
# build variable is not a secret read, and a guard that refuses one is a guard people switch off.
for line in "make PREFIX=/usr/local install" "cargo build --features a=b" "tool -rf build"; do
  [ "$(keycmd "$line" "$policy")" = 0 ] \
    || fail "\`$line\` was refused: an ordinary assignment is not a path rule"
done
note "an ordinary assignment stays ordinary"

# The mutant behind the claim: with the one pattern that names this file gone, the environment prefix
# has to go green again. Without it the assertion above could be resting on something else entirely
# -- a guard that refused every command line would satisfy it just as happily.
policy_mutant assignment-value-unmatched drop-pattern:'**/*keyring*.json*' \
  cmd:"STORE_ROOT=$keys/keyring.json tool run" 0

## A path that is a wrapper's operand ##########################################
# The same fault as the section above, one token further along, and it stayed open through it. The
# program search skips a wrapper's flags and takes the next token as the program -- so a flag
# spending that position on a *separated* operand hands the path to the search instead of to the
# rules. `xargs -a <store> cat` was measured admitted on the built binary while `cat <store>` was
# refused, and so was every other wrapper flag of that shape. The attached spellings were already
# recovered as values inside a token, which is why only the separated one was left to find.
#
# Every wrapper flag, not a list of the ones that take paths: which of a wrapper's flags take one is
# not something a command line says, so a flag this cannot rule out is read as taking a path.
echo "→ a path handed to a wrapper as its own flag's operand is a candidate"
for line in "xargs -a $keys/keyring.json cat" \
            "xargs --arg-file $keys/keyring.json cat" \
            "env -C $keys/keyring.json ls" \
            "env --chdir $keys/keyring.json ls" \
            "sudo -D $keys/keyring.json ls" \
            "sudo --chroot $keys/keyring.json ls" \
            "doas -C $keys/keyring.json ls" \
            "time -o $keys/keyring.json ls" \
            "stdbuf -o $keys/keyring.json ls" \
            "nohup -x $keys/keyring.json ls" \
            "xargs -0 -a $keys/keyring.json cat" \
            "sudo -n env -C $keys/keyring.json ls" \
            "xargs -a$keys/keyring.json cat" \
            "xargs --arg-file=$keys/keyring.json cat"; do
  [ "$(keycmd "$line" "$policy")" = 2 ] \
    || fail "\`$line\` was admitted: a wrapper's flag operand never became a candidate path"
done
note "separated, attached, long-form, behind another flag and behind another wrapper, all refused"

# What that costs, on the same real filesystem and from inside the key store, which is the worst
# place for it: a flag whose operand is a word now offers that word to the path rules. It resolves
# to a name in the working directory, which is what an ordinary argument already does -- and
# nothing in this policy matches a bare word, which is the property the role-word section keeps.
for line in "sudo -u postgres psql" "sudo -n rm -rf build" "env -u EDITOR ls" \
            "nice -n 5 make" "timeout -k 1 5 cargo build" "stdbuf -oL grep x file" \
            "xargs -n 1 echo" "make PREFIX=/usr/local install" "awk -v x=1 '{print}'" \
            "cc -I/usr/include -c a.c" "which bash" "ls -la /bin/sh"; do
  [ "$(keycmd "$line" "$policy")" = 0 ] \
    || fail "\`$line\` was refused: a flag's operand that is a word is not a secret read"
done
note "a user, a signal, a niceness and a buffer mode stay words rather than becoming paths"

# The mutant behind it. Dropping the wrapper list would not do -- with `xargs` no longer a wrapper
# the operand is an ordinary argument and stays refused -- so what carries this claim is the one
# pattern that names the file. Take it away and the operand has to go green again, which is what
# separates "the path became a candidate" from "the guard refuses command lines".
policy_mutant wrapper-operand-unmatched drop-pattern:'**/*keyring*.json*' \
  cmd:"xargs -a $keys/keyring.json cat" 0

## A program handed to an interpreter ##########################################
# The widest shape left after the section above, and the one this deployment had already declared and
# never enforced: `sh -c '<line>'` was admitted where the same line typed directly was refused,
# because the whole call sits inside one quoted word and every rule fires on something the parser
# found. It is refused as a *shape* rather than recursed into. Recursing means ruling on which
# programs take a command line and which take a program -- and reading a program as a command line
# errs permissive, which is the one direction this gate does not err in.
#
# Asserted here as well as in the cargo tests for the same reason the two sections above are: these
# run a real policy file through the built binary, from inside a directory that holds real key
# material, which is where a canonicalised path and a cwd-relative candidate are the actual inputs.

echo "→ a program handed to an interpreter is refused as a shape"
for line in "sh -c 'cat $keys/keyring.json'" \
            "bash -c true" "zsh -c true" "dash -c true" \
            "python3 -c 'print(1)'" "perl -e 1" "ruby -e 1" "node -e 1" \
            "bash -lc true" "sh -ctrue" "sh --command=true" \
            "sh -" "sh /dev/stdin" "sh" "echo hi | bash" \
            "env sh -c true" "xargs sh -c true" "timeout 5 sh -c true" \
            "find . -exec sh -c true ;"; do
  [ "$(keycmd "$line" "$policy")" = 2 ] \
    || fail "\`$line\` was admitted: the program inside the argument was never read, so nothing refused it"
done
note "clustered, attached, long-form, on stdin, behind a wrapper and behind find -exec, all refused"

# The shape the section above reported still open, and it is not about `timeout`. The program search
# skips flags and assignments and takes the next token, so a wrapper spending that position on a
# separated operand -- `timeout 5`, `nice -n 5` -- leaves the interpreter in the arguments, where the
# empty tail of an interpreter reading standard input looked like a mention. Every wrapper whose
# operand is attached or absent was already refused above, which is why this went unseen.
for line in "timeout 5 sh" "nice -n 5 sh" "timeout 5 bash" "timeout 5 python3" \
            "timeout 5 /bin/sh" "timeout -k 1 5 sh" "sudo timeout 5 sh" \
            "timeout 5 timeout 3 sh"; do
  [ "$(keycmd "$line" "$policy")" = 2 ] \
    || fail "\`$line\` was admitted: a wrapper's operand hid the interpreter that ends the line"
done
note "an interpreter ending the line behind a wrapper's operand is refused, nested and multi-operand alike"

# What that costs, and the line it is drawn at. An interpreter handed a *file* is not refused: the
# file is at a path the path rules already read, it got there through a write gate, and a `#!` line
# runs it as `./script` with no interpreter in the command at all -- so refusing the spelling buys no
# property while breaking every installer in this repository.
for line in "sh install.sh" "bash -n install.sh" "python3 tool.py --verbose" \
            "node server.js" "bash --version" "which bash" "ls -la /bin/sh" \
            "grep -c sh README.md" \
            "timeout 5 sh install.sh" "timeout 5 bash --version"; do
  [ "$(keycmd "$line" "$policy")" = 0 ] \
    || fail "\`$line\` was refused: an interpreter handed a file is not an inline program"
done
note "a script file, a syntax check, a version flag and a mention of an interpreter stay admitted"

# Two mutants, because two separate things in the document carry this claim and one mutant would
# leave the other resting on nothing: which programs are interpreters, and which token hands one a
# program. Each has to flip the same probe on its own.
policy_mutant interpreter-unlisted drop-interpreter:sh cmd:"sh -c true" 0
policy_mutant inline-flag-unlisted drop-flag:c cmd:"sh -c true" 0

# And two for the shape behind a wrapper's operand, which rests on a third thing in the document
# neither mutant above can reach: the wrapper list. Drop `timeout` from it and the line stops being
# read as a wrapper at all, so the interpreter is a mention again and the refusal goes away -- which
# is the state this gate was in before today.
policy_mutant wrapper-unlisted drop-wrapper:timeout cmd:"timeout 5 sh" 0
policy_mutant wrapped-interpreter-unlisted drop-interpreter:sh cmd:"timeout 5 sh" 0

## A program that is a wrapper's operand #######################################
# The last hole of this family, and the half the section above did not close. Making a wrapper's
# operand a candidate *path* said nothing about the token behind it: the program search still
# settles on the operand, so the program the line runs stays in the argument list where no *program*
# rule reaches it. Measured admitted on the built binary -- `timeout 5 rm -rf /`, `sudo -u root nc -l
# 1234` and `xargs -a <file> nc -l 1234` -- while `rm -rf /` and `sudo nc -l 1234` were refused.
#
# Which token is the program cannot be recovered: counting a wrapper's operands is exactly what this
# parse cannot do, and a parse that could count them would not have had the gap. So behind a wrapper
# every token that could be a program name is offered to the program rules, and all of them ask the
# same question -- the command list, the writing list and the egress list alike.
echo "→ a program reached through a wrapper's operand is matched by the program rules"
for line in "timeout 5 rm -rf /" "sudo -u root rm -rf /" \
            "timeout 5 nc -l 1234" "sudo -u root nc -l 1234" \
            "xargs -a list.txt nc -l 1234" "timeout -k 1 5 nc -l 1234" \
            "sudo timeout 5 /usr/bin/nc -l 1234" "timeout 5 ssh host uptime" \
            "timeout 5 git push --force" "nice -n 5 shutdown now" \
            "env -u LANG dd if=/dev/zero of=out.img"; do
  [ "$(keycmd "$line" "$policy")" = 2 ] \
    || fail "\`$line\` was admitted: a wrapper's operand hid the program the line runs"
done
note "a destructive program, a socket, a rewrite and a power state, each behind a wrapper's operand"

# What that costs, measured rather than estimated, and this is the whole of it: a token that merely
# looks like a program name is refused as one. The list is bounded by the policy -- a word matters
# only where the document already names it as a program -- and the last of these is the widest: an
# egress program past a wrapper's operand keeps its own name in the argument list, where the egress
# screen reads a bare word as a host, so even an allowlisted target is refused.
for line in "timeout 30 cargo build --bin ssh" "env grep -rn ssh ." \
            "timeout 5 grep -c sh notes" "timeout 5 grep -rn touch /usr/include" \
            "timeout 5 cat /etc/passwd" "timeout 5 echo curl" \
            "timeout 5 curl http://127.0.0.1:8080/health"; do
  [ "$(keycmd "$line" "$policy")" = 2 ] \
    || fail "\`$line\` was admitted, and this section claims it is refused: the cost is not what it says"
done
note "a binary target, a search term, a mention, a filename and an allowlisted fetch: the cost, stated"

# And what it does not cost, on the same real filesystem: a word that names nothing in the policy is
# still a word, a wrapper that spends no operand leaves the program where the search finds it, and
# every line without a wrapper is untouched.
for line in "timeout 30 cargo build --bin app" "timeout -k 1 5 cargo build" \
            "sudo -n rm -rf build" "nice -n 5 make" "env -u EDITOR ls" "xargs -n 1 echo" \
            "timeout 5 sh install.sh" "timeout 5 bash --version" "timeout 5 cat README.md" \
            "sudo -u ci make install" "grep -c sh README.md" "cargo build --bin ssh" \
            "which bash" "ls -la /bin/sh" "make PREFIX=/usr/local install" \
            "curl http://127.0.0.1:8080/health" "sudo curl http://127.0.0.1:8080/health" \
            "xargs -n1 curl http://127.0.0.1:8080/health"; do
  [ "$(keycmd "$line" "$policy")" = 0 ] \
    || fail "\`$line\` was refused: promoting a token behind a wrapper cost more than it claims"
done
note "ordinary work behind a wrapper, and every fetch whose program stays in the program position"

# Two mutants, because two things in the document carry this claim and one would leave the other
# resting on nothing: that the rule names the program, and that the parser walks the wrapper. Note
# the asymmetry with the path half above, where dropping the wrapper leaves the operand an ordinary
# argument and the refusal stands -- here the tail becomes ordinary arguments that name no path
# rule, so the line goes green and the mutant is caught.
policy_mutant wrapped-program-unnamed drop-command-program:nc cmd:"timeout 5 nc -l 1234" 0
policy_mutant wrapped-program-unwrapped drop-wrapper:timeout cmd:"timeout 5 nc -l 1234" 0

## A redirection into a device that stores nothing #############################
# The one false positive in this family, and the only exemption in the document. `/dev/**` is system
# configuration, so `> /dev/null` was a refusal -- the most ordinary line a shell has, once per turn
# on any deployment whose agents can run commands at all. Four device nodes are exempt as
# *redirection targets*, matched as the literal spelling on the line.
#
# Literal rather than glob, because this group admits where every other one denies: a loose denial
# costs a false refusal and a loose admission hands over the disk. Literal rather than resolved,
# because `/dev/stdout` canonicalises to whatever descriptor 1 is bound to in whichever process
# asks -- which on this filesystem is a pipe, and is why that spelling is asserted here rather than
# only in the cargo tests.
echo "→ an ordinary redirect into a device that stores nothing is admitted"
for line in "date > /dev/null" "tool check > /dev/null 2>&1" "echo hi 2>/dev/null" \
            "date >/dev/null" "date >>/dev/null" "tool run >/dev/stdout" \
            "tool run 2>/dev/stderr" "tool run >/dev/zero"; do
  [ "$(keycmd "$line" "$policy")" = 0 ] \
    || fail "\`$line\` was refused: a redirect into a null device is not a write to the system"
done
note "a discard, a discard of both streams, an append and the two standard streams by name"

# What the exemption does not reach, and this is the whole of what keeps the rule it punches
# through. Four literal paths, so no fifth inherits it: a real device stays refused, both
# descriptor spellings stay refused -- `/dev/fd/N` names whatever a descriptor this guard cannot
# see was bound to -- and a *writing program* naming the same path is not a redirection, so
# `rm /dev/null` still removes nothing.
echo "→ and it reaches no device that stores anything, and no other way of naming one"
for line in "echo x > /dev/disk0" "echo x > /dev/rdisk0" "echo x > /dev/sda" \
            "echo x > /dev/mem" "echo x > /dev/tty" "echo x > /dev/urandom" \
            "echo x > /dev/fd/3" "echo x > /dev/stdin" \
            "dd if=/dev/zero of=/dev/disk0" "rm /dev/null" "tee /dev/null" \
            "sh /dev/stdin" "sh /dev/fd/0" \
            "cat $keys/keyring.json > /dev/null"; do
  [ "$(keycmd "$line" "$policy")" = 2 ] \
    || fail "\`$line\` was admitted: the device exemption reached further than the paths it names"
done
note "a disk, a raw disk, kernel memory, a tty, both descriptor spellings, and a secret read past a discard"

# The mutant behind the new claim. One entry out of the list and the most ordinary line on the host
# has to go dark again -- which is what separates "the exemption admitted it" from "nothing in the
# document refused it in the first place".
policy_mutant redirect-sink-unlisted drop-sink:/dev/null cmd:"date > /dev/null" 2

echo "→ installing into a scratch project"
HARNESS_PROJECT_DIR="$work" harnesses/claude-code/install.sh \
  --guard "$guard" --policy "$PWD/spec/tool-policy.json" >/dev/null
settings="$work/.claude/settings.json"
[ -f "$settings" ] || fail "no settings file was written"

python3 - "$settings" <<'PY' || status=1
import json, sys
settings = json.load(open(sys.argv[1]))
hooks = settings.get("hooks", {}).get("PreToolUse", [])
deny = settings.get("permissions", {}).get("deny", [])
problems = []
if len(hooks) != 1:
    problems.append(f"expected one PreToolUse entry, found {len(hooks)}")
else:
    commands = [hook.get("command", "") for hook in hooks[0].get("hooks", [])]
    if not any("harness-guard" in command for command in commands):
        problems.append("the hook does not invoke the guard")
if not any(entry.startswith("Read(") for entry in deny):
    problems.append("no read denies were generated")
if not any(entry.startswith("Bash(") for entry in deny):
    problems.append("no command denies were generated")
for problem in problems:
    print(f"::error::generated settings: {problem}")
sys.exit(1 if problems else 0)
PY

echo "→ a second run keeps a settings file it did not write"
HARNESS_PROJECT_DIR="$work" harnesses/claude-code/install.sh \
  --guard "$guard" --policy "$PWD/spec/tool-policy.json" >/dev/null
[ -f "$work/.claude/settings.harness-policy.json" ] || fail "an existing settings file was overwritten"

echo "→ the wired hook refuses and permits"
hook="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["hooks"]["PreToolUse"][0]["hooks"][0]["command"])' "$settings")"
check() {
  local payload="$1" expected="$2"
  set +e
  printf '%s' "$payload" | $hook >/dev/null 2>&1
  local code=$?
  set -e
  if [ "$code" != "$expected" ]; then
    fail "expected exit $expected, got $code, for $payload"
  else
    note "exit $code — $payload"
  fi
}
check '{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}' 2
check '{"tool_name":"Bash","tool_input":{"command":"ls && sudo rm -rf ~"}}' 2
check '{"tool_name":"WebFetch","tool_input":{"url":"https://unlisted.test/x"}}' 2
check '{"tool_name":"Read","tool_input":{"file_path":"README.md"}}' 0

echo "→ installing into a scratch runtime home"
home="$work/hermes-home"
mkdir -p "$home"
harnesses/hermes/install.sh --target "$home" \
  --guard "$guard" --policy "$PWD/spec/tool-policy.json" >/dev/null
fragment="$home/cli-config.yaml"
[ -f "$fragment" ] || fail "no config was written"

python3 - "$fragment" <<'YAMLCHECK' || status=1
import sys

text = open(sys.argv[1]).read()
try:
    import yaml

    config = yaml.safe_load(text)
except ImportError:  # No YAML reader here; check the shape textually instead.
    config = None

problems = []
if config is None:
    if "\nhooks:\n  pre_tool_call:\n    - command: " not in text:
        problems.append("no hooks.pre_tool_call entry")
    if "harness-guard" not in text:
        problems.append("the hook does not invoke the guard")
else:
    entries = config.get("hooks", {}).get("pre_tool_call")
    if not isinstance(entries, list) or len(entries) != 1:
        problems.append(f"expected one pre_tool_call entry, found {entries!r}")
    else:
        entry = entries[0]
        if "harness-guard" not in entry.get("command", ""):
            problems.append("the hook does not invoke the guard")
        if not isinstance(entry.get("timeout"), int):
            problems.append("the hook has no integer timeout")
        # A matcher would narrow the hook to the tools it names, leaving the rest unchecked.
        if "matcher" in entry:
            problems.append("the hook carries a matcher")
for problem in problems:
    print(f"::error::generated config: {problem}")
sys.exit(1 if problems else 0)
YAMLCHECK

echo "→ a second run keeps a config file it did not write"
harnesses/hermes/install.sh --target "$home" \
  --guard "$guard" --policy "$PWD/spec/tool-policy.json" >/dev/null
[ -f "$home/cli-config.harness-policy.yaml" ] || fail "an existing config was overwritten"
grep -q 'pre_tool_call' "$fragment" || fail "the config that was kept is not the generated one"

echo "→ a missing runtime home is an error, not a config written where nothing reads it"
if harnesses/hermes/install.sh --target "$work/absent" --guard "$guard" >/dev/null 2>&1; then
  fail "installing into a nonexistent home reported success"
fi
if [ -e "$work/absent" ]; then fail "installing into a nonexistent home created it"; fi

echo "→ the wired hook says its refusal where that harness reads it"
hermes_hook="$(sed -n 's/^ *- command: "\(.*\)"$/\1/p' "$fragment")"
[ -n "$hermes_hook" ] || fail "no hook command could be read back out of the config"

# That runtime parses the verdict out of stdout and reads empty stdout as no opinion, so the exit
# code alone proves nothing here — the block has to be *said*.
blocked() {
  python3 -c 'import json,sys
d = json.load(sys.stdin)
sys.exit(0 if d.get("decision") == "block" and d.get("reason") else 1)'
}
verdict() {
  local payload="$1" expected="$2" said code
  set +e
  said="$(printf '%s' "$payload" | $hermes_hook 2>/dev/null)"
  code=$?
  set -e
  [ "$code" = "$expected" ] || fail "expected exit $expected, got $code, for $payload"
  if [ "$expected" = 2 ]; then
    if printf '%s' "$said" | blocked; then
      note "exit $code, block on stdout — $payload"
    else
      fail "a block said nothing readable on stdout (${said:-empty}) for $payload"
    fi
  elif [ -n "$said" ]; then
    fail "a permitted call said something on stdout ($said) for $payload"
  else
    note "exit $code, silent — $payload"
  fi
}
envelope() {
  printf '{"hook_event_name":"pre_tool_call","tool_name":"%s","tool_input":%s,' "$1" "$2"
  printf '"session_id":"s","cwd":".","extra":{}}'
}
verdict "$(envelope terminal '{"command":"cat ~/.ssh/id_rsa"}')" 2
verdict "$(envelope terminal '{"command":"ls && sudo rm -rf ~"}')" 2
verdict "$(envelope web_extract '{"url":"https://unlisted.test/x"}')" 2
verdict "$(envelope read_file '{"path":"README.md"}')" 0
# The wrong harness, a renamed field, arguments that were not a mapping: blocks that would otherwise
# arrive only as an exit code this runtime does not read.
verdict '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' 2
## OpenClaw ###################################################################
# This harness reaches the tool-call boundary through a plugin rather than a hook command, and its
# config is one large file holding credentials. So what is tested here is different: that the
# installer refuses to touch that file, that the fragment it prints is real, and that the plugin
# fails closed.

oc="harnesses/openclaw/install.sh"
ocwork="$work/openclaw"
mkdir -p "$ocwork/state" "$ocwork/plug"
config="$ocwork/state/openclaw.json"
printf '{"gateway":{"port":19001}}\n' > "$config"

echo "→ the openclaw installer refuses a target that is not there"
set +e
"$oc" --guard "$guard" --config "$ocwork/state/absent.json" --plugin-dir "$ocwork/plug" \
  >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the installer succeeded with no config to merge into"

echo "→ installing beside a config it must not touch"
before="$(cat "$config")"
"$oc" --guard "$guard" --policy "$PWD/spec/tool-policy.json" \
  --config "$config" --plugin-dir "$ocwork/plug" >/dev/null
fragment="$ocwork/plug/config-fragment.json"
[ -f "$fragment" ] || fail "no config fragment was written"
for file in index.mjs openclaw.plugin.json package.json; do
  [ -f "$ocwork/plug/$file" ] || fail "the plugin is missing $file"
done
[ "$(cat "$config")" = "$before" ] || fail "the installer edited the live config"

echo "→ the fragment is valid JSON and carries what it claims"
cat > "$work/fragment-assertions.py" <<'PY'
import json, sys
fragment, plugin_dir, expect_gate = sys.argv[1], sys.argv[2], sys.argv[3]
config = json.load(open(fragment))
problems = []

# Layer 1 is the one part of this fragment that can take an agent's ability to act away. The Claude
# CLI backend reads the exec gate as full-and-off or nothing at all, so a strict gate with no command
# pre-approved refuses every native tool call -- and recall keeps working, so the agent answers from
# memory and writes nothing, with a config that validates and a policy that renders as a table. The
# claim is therefore a coupling, checked in both directions: a strict gate exactly when the backend
# argv pinned beside it pre-approves something.
def pre_approves(argv):
    return any(
        "".join(c for c in str(word).split("=")[0] if c.isalnum()).lower() == "allowedtools"
        for word in argv
    )

exec_gate = config.get("tools", {}).get("exec", {})
strict = bool(exec_gate) and (exec_gate.get("security") != "full" or exec_gate.get("ask") != "off")
pinned = (
    config.get("agents", {}).get("defaults", {}).get("cliBackends", {})
    .get("claude-cli", {}).get("args", [])
)
if strict and not pre_approves(pinned):
    problems.append(
        f"a strict exec gate {exec_gate} is pinned beside {pinned}, which pre-approves nothing: "
        "every native tool call on that backend would be refused"
    )
if pinned and not strict:
    problems.append(f"the backend argv {pinned} is pinned with no exec gate for it to survive")
if (expect_gate == "yes") != strict:
    problems.append(f"expected a strict exec gate: {expect_gate}, found {exec_gate!r}")
if strict:
    if exec_gate.get("security") != "allowlist":
        problems.append(f"exec security is {exec_gate.get('security')!r}, not default-deny")
    if exec_gate.get("ask") != "on-miss":
        problems.append(f"exec ask is {exec_gate.get('ask')!r}, so a miss would not reach a person")

plugins = config.get("plugins", {})
paths = plugins.get("load", {}).get("paths", [])
if paths != [plugin_dir]:
    problems.append(f"load paths are {paths}, not the directory the plugin was installed to")
if any("${" in path for path in paths):
    problems.append("a placeholder survived into the fragment, so the plugin would never load")

entry = plugins.get("entries", {}).get("harness-tool-policy")
if not entry:
    problems.append("the guard plugin has no entry, so it is installed and not enabled")
else:
    if entry.get("enabled") is not True:
        problems.append("the guard plugin entry is not enabled")
    argv = entry.get("config", {}).get("guard")
    if not isinstance(argv, list) or not argv:
        problems.append(f"the guard is {argv!r}, not an argv the plugin can spawn")
    elif "--harness" not in argv or "openclaw" not in argv:
        problems.append(f"the guard argv does not select this harness: {argv}")
    # This hook has no host-side default timeout, so an unbounded handler wedges the tool call.
    plugin_budget = entry.get("config", {}).get("timeoutMs")
    host_budget = entry.get("hooks", {}).get("timeouts", {}).get("before_tool_call")
    if not isinstance(plugin_budget, int) or not isinstance(host_budget, int):
        problems.append(f"the hook is unbounded: plugin={plugin_budget!r} host={host_budget!r}")
    elif host_budget <= plugin_budget:
        problems.append("the host would time out first, and its refusal names no rule")

# The one thing this harness must NOT claim: its node deny list matches command ids, not shell text.
rendered = json.dumps(config)
if "denyCommands" in rendered:
    problems.append("the fragment claims a command deny list this harness cannot apply")

for problem in problems:
    print(f"::error::generated fragment: {problem}")
sys.exit(1 if problems else 0)
PY
python3 "$work/fragment-assertions.py" "$fragment" "$ocwork/plug" no || status=1

echo "→ the guard the fragment names refuses and permits"
# Read the argv the plugin would spawn, so what is exercised is the fragment's own wiring rather
# than a command line this script composed.
mapfile -t ocargv < <(python3 -c \
  'import json,sys; print(*json.load(open(sys.argv[1]))["plugins"]["entries"]["harness-tool-policy"]["config"]["guard"], sep="\n")' \
  "$fragment")
occheck() {
  local payload="$1" expected="$2" code
  set +e
  printf '%s' "$payload" | "${ocargv[@]}" >/dev/null 2>&1
  code=$?
  set -e
  if [ "$code" != "$expected" ]; then
    fail "openclaw: expected exit $expected, got $code, for $payload"
  else
    note "exit $code — $payload"
  fi
}
occheck '{"toolName":"exec","params":{"command":"cat ~/.ssh/id_rsa"}}' 2
occheck '{"toolName":"exec","params":{"command":"ls && sudo rm -rf ~"}}' 2
occheck '{"toolName":"web_fetch","params":{"url":"https://unlisted.test/x"}}' 2
occheck '{"toolName":"apply_patch","params":{},"derivedPaths":["/etc/crontab"]}' 2
occheck '{"toolName":"read","params":{"path":"README.md"}}' 0
# A program is not a command line. Reading it as one permits what the shell line it builds would not.
occheck '{"toolName":"exec","toolKind":"code_mode_exec","params":{"command":"await sh(\"ls\")"}}' 2

echo "→ a second run changes nothing"
digest="$(cat "$fragment" "$ocwork/plug/index.mjs" | cksum)"
"$oc" --guard "$guard" --policy "$PWD/spec/tool-policy.json" \
  --config "$config" --plugin-dir "$ocwork/plug" >/dev/null
[ "$(cat "$fragment" "$ocwork/plug/index.mjs" | cksum)" = "$digest" ] \
  || fail "a second run rewrote the plugin or the fragment differently"
[ "$(cat "$config")" = "$before" ] || fail "a second run edited the live config"

echo "→ layer 1 is emitted only together with the pre-approvals that survive it"
ocpinned="$ocwork/plug-pinned"
"$oc" --guard "$guard" --policy "$PWD/spec/tool-policy.json" \
  --config "$config" --plugin-dir "$ocpinned" \
  --backend-arg --allowedTools --backend-arg 'Bash(git status:*),Read' >/dev/null
python3 "$work/fragment-assertions.py" "$ocpinned/config-fragment.json" "$ocpinned" yes || status=1
grep -q 'Bash(git status:\*),Read' "$ocpinned/config-fragment.json" \
  || fail "a pre-approval carrying a space did not survive as one argument"

echo "→ and the shape that would refuse every native tool call is refused instead of written"
set +e
"$guard" emit --harness openclaw --backend-arg --verbose \
  >"$ocwork/bricked.json" 2>"$ocwork/bricked.err"
code=$?
set -e
[ "$code" -ne 0 ] || fail "emit paired a strict exec gate with backend args that pre-approve nothing"
if [ -s "$ocwork/bricked.json" ]; then
  fail "a refused fragment was printed anyway, so it could still be applied"
fi
grep -q -- '--allowedTools' "$ocwork/bricked.err" \
  || fail "the refusal does not name what the backend argv is missing"

echo "→ it will not overwrite somebody else's plugin directory"
other="$ocwork/other"
mkdir -p "$other"
printf '{"id":"some-other-plugin"}\n' > "$other/openclaw.plugin.json"
set +e
"$oc" --guard "$guard" --config "$config" --plugin-dir "$other" >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the installer overwrote a directory holding another plugin"
grep -q 'some-other-plugin' "$other/openclaw.plugin.json" \
  || fail "the other plugin's manifest was replaced"

echo "→ --apply refuses to drop load paths a patch would replace"
stub="$ocwork/bin"
mkdir -p "$stub"
cat > "$stub/openclaw" <<'STUB'
#!/usr/bin/env bash
# Enough of the harness CLI to answer the one question the installer asks before it applies.
if [ "$1" = "config" ] && [ "$2" = "get" ]; then
  echo '["/opt/somebody-elses-plugin"]'
  exit 0
fi
echo "stub: refusing to run $*" >&2
exit 1
STUB
chmod +x "$stub/openclaw"
set +e
"$oc" --guard "$guard" --config "$config" --plugin-dir "$ocwork/plug" \
  --openclaw "$stub/openclaw" --apply >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "--apply would have replaced an existing plugins.load.paths"

echo "→ the plugin fails closed"
if command -v node >/dev/null 2>&1; then
  node --input-type=module - "$guard" <<'JS' || status=1
import { consult } from "./harnesses/openclaw/plugin/index.mjs";

const guard = [process.argv[2], "check", "--harness", "openclaw"];
const silent = { warn() {} };
const problems = [];
const blocked = (result) => Boolean(result && result.block);

// A refusal the policy makes, and a call it permits: the plugin must pass both through unchanged.
if (!blocked(await consult(guard, 5000, { toolName: "exec", params: { command: "cat ~/.ssh/id_rsa" } }, silent)))
  problems.push("a denied call was let through");
if (blocked(await consult(guard, 5000, { toolName: "read", params: { path: "README.md" } }, silent)))
  problems.push("a permitted call was blocked");

// Every way the guard can fail to answer has to end in a refusal, not a pass.
if (!blocked(await consult([], 5000, { toolName: "exec", params: { command: "ls" } }, silent)))
  problems.push("an unconfigured guard let a call through");
if (!blocked(await consult(["/nonexistent/guard"], 5000, { toolName: "exec", params: { command: "ls" } }, silent)))
  problems.push("a guard that cannot be started let a call through");
if (!blocked(await consult(["/bin/sleep", "5"], 150, { toolName: "exec", params: { command: "ls" } }, silent)))
  problems.push("a guard that never answered let a call through");

for (const problem of problems) console.log(`::error::openclaw plugin: ${problem}`);
process.exit(problems.length ? 1 : 0);
JS
  [ "$status" -eq 0 ] && note "refuses on deny, on no guard, on no binary and on no answer"
else
  fail "node is not installed, so the plugin's decision path went untested"
fi
## OpenClaw recall #############################################################
# The other half of that harness: a plugin owning the memory slot that recalls before a reply. What
# is tested here is the opposite of what is tested above — this one must fail *open*. A lookup that
# cannot answer has to let the turn through, and it has to stay distinguishable in the log from a
# lookup that legitimately found nothing.

ocmem="harnesses/openclaw/install-memory.sh"
memwork="$work/openclaw-memory"
mkdir -p "$memwork/state" "$memwork/plug" "$memwork/bin"
memconfig="$memwork/state/openclaw.json"
printf '{"gateway":{"port":19002}}\n' > "$memconfig"

# Stand-ins for the read tool, one per answer it can give. Each ignores its arguments except the one
# that records them: what the plugin appends to the configured argv is part of the wiring.
reader() { echo "$memwork/bin/reader-$1"; }
cat > "$(reader records)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
cat <<'JSON'
{"records":[
 {"record_id":"01AAAA","received_at":"2026-01-01T00:00:00Z","action":"deploy","outcome":"ok",
  "agent":"builder","entities":[{"kind":"service","id":"api"}],"attrs":{"env":"staging"},
  "tags":["release"]},
 {"record_id":"01BBBB","received_at":"2026-01-02T00:00:00Z","action":"review","outcome":"failed",
  "agent":"builder","entities":[{"kind":"pull_request","id":"12"}],"attrs":{},"tags":[]}],
 "degraded":false,"omitted":[],"token_estimate":57}
JSON
STUB
cat > "$(reader empty)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
printf '{"records":[],"degraded":false,"omitted":[],"token_estimate":0}'
STUB
# Empty for the bundle, a hit for the search: the only reader that can tell the two reads apart, and
# the only way to exercise a fallback that fires because the precise question missed.
cat > "$(reader fallback)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
if [ "${1:-}" = "records" ]; then
  # A window, for the one assertion that asks whether a ranked hit takes the turn from the digest.
  printf '{"records":[{"record_id":"01WINDOW","received_at":"2026-08-28T06:22:34Z","action":"deploy","outcome":"success","agent":"deploy_bot","entities":[],"attrs":{},"tags":[]}],"token_estimate":9}'
elif [ "${1:-}" = "search" ]; then
  cat <<'JSON'
{"records":[{"record_id":"01SEARCH","received_at":"2026-01-05T00:00:00Z","action":"import",
 "outcome":"success","agent":"memory_import","entities":[],"attrs":{"source":"2026-03-13.md"},
 "tags":["imported"]}],
 "degraded":false,"omitted":[],"token_estimate":18}
JSON
else
  printf '{"records":[],"degraded":false,"omitted":[],"token_estimate":0}'
fi
STUB
cat > "$(reader degraded)" <<'STUB'
#!/usr/bin/env bash
cat <<'JSON'
{"records":[{"record_id":"01CCCC","received_at":"2026-01-03T00:00:00Z","action":"deploy",
 "outcome":"ok","agent":"builder","entities":[],"attrs":{},"tags":[]}],
 "degraded":true,"omitted":["entity timeline was not consulted in time"],"token_estimate":22}
JSON
STUB
cat > "$(reader refused)" <<'STUB'
#!/usr/bin/env bash
echo "the service refused this request (400): unknown parameter" >&2
exit 8
STUB
# Answers one read and one only: the one naming the thread its record was filed under. Anything else
# gets the empty page a bundle returns for an entity nothing was written about — so a turn that fails
# to name the thread cannot pass by being answered anyway.
cat > "$(reader thread)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
case " $* " in
  *"--entity=chat_thread:c0example/1700000000.000100"*)
    cat <<'JSON'
{"records":[{"record_id":"01THREAD","received_at":"2026-01-04T00:00:00Z","action":"note",
 "outcome":"ok","agent":"someone_else",
 "entities":[{"kind":"chat_thread","id":"c0example/1700000000.000100"}],
 "attrs":{},"tags":[]}],"degraded":false,"omitted":[],"token_estimate":31}
JSON
    ;;
  *) printf '{"records":[],"degraded":false,"omitted":[],"token_estimate":0}' ;;
esac
STUB
# The digest reads a window with `records`, and these three tell the window read apart from the two
# that answer the turn. A digest that fired on a `bundle` would be indistinguishable from recall in
# every one of the assertions below, so each of these answers exactly one shape.
#
# Two dates on purpose: a digest groups by date, and a single-date fixture would pass a renderer that
# had lost the grouping entirely.
cat > "$(reader digest)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
if [ "${1:-}" = "records" ]; then
  cat <<'JSON'
{"records":[
 {"record_id":"01DAY2","received_at":"2026-08-28T06:22:34Z","action":"deploy","outcome":"success",
  "agent":"deploy_bot","entities":[{"kind":"commit","id":"example/service@1a2b3c4"}],"attrs":{},"tags":[]},
 {"record_id":"01DAY1","received_at":"2026-08-26T09:20:43Z","action":"answer","outcome":"partial",
  "agent":"main_bot","entities":[{"kind":"ticket","id":"PROJ-42"}],"attrs":{},"tags":[]}],
 "token_estimate":40}
JSON
else
  printf '{"records":[],"degraded":false,"omitted":[],"token_estimate":0}'
fi
STUB
# Answers the window and refuses everything else: the reader for "one read of the pair worked".
cat > "$(reader digest-only)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
if [ "${1:-}" = "records" ]; then
  printf '{"records":[{"record_id":"01WINDOW","received_at":"2026-08-28T06:22:34Z","action":"deploy","outcome":"success","agent":"deploy_bot","entities":[],"attrs":{},"tags":[]}],"token_estimate":9}'
else
  echo "the service refused this request (400): unknown parameter" >&2
  exit 8
fi
STUB
# And the mirror of it: the turn's own reads answer, the window read does not.
cat > "$(reader digest-broken)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
if [ "${1:-}" = "records" ]; then
  echo "the service refused this request (400): unknown parameter" >&2
  exit 8
fi
printf '{"records":[],"degraded":false,"omitted":[],"token_estimate":0}'
STUB
# Answers one read and one only: the one asking about the *writer name* `main_bot`. An `--actor
# main` -- the agent id, which is what shipped -- gets the empty page a bundle returns for a writer
# nothing was ever filed under, so an assertion here cannot pass by being answered anyway. This is
# the store's own behaviour: measured on the live deployment, `--actor main`, `--actor pr` and
# `--actor deploy` returned 0 records each while `main_bot`, `pr_bot` and `deploy_bot` returned 8.
cat > "$(reader actor)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
case " $* " in
  *" --actor main_bot "*)
    cat <<'JSON'
{"records":[{"record_id":"01ACTOR","received_at":"2026-08-27T00:00:00Z","action":"answer",
 "outcome":"ok","agent":"main_bot","entities":[],"attrs":{},"tags":[]}],
 "degraded":false,"omitted":[],"token_estimate":14}
JSON
    ;;
  *) printf '{"records":[],"degraded":false,"omitted":[],"token_estimate":0}' ;;
esac
STUB
# The reader for the actor's *bounded* page: it can tell the read that answers the turn from the read
# that fetches the background, and answers each differently. Nothing else here can -- `reader-actor`
# answers one read only, which is what an assertion about two reads cannot be built on.
#
# The actor branch answers three records and reports itself `degraded`, which is what the live service
# does for any actor asked for fewer rows than it has: `--limit N` reads N+1 so that "there is more"
# is a fact rather than a guess, and the extra row is an omission. On the deployment this was measured
# on, `main_bot` had more history than any page it will ever be given, so that flag was on for ever.
# **The answer must not inherit it**, and this fixture is what makes that assertable.
cat > "$(reader background)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
if [ "${1:-}" = "records" ]; then
  cat <<'JSON'
{"records":[
 {"record_id":"01DAY2","received_at":"2026-08-28T06:22:34Z","action":"deploy","outcome":"success",
  "agent":"deploy_bot","entities":[{"kind":"commit","id":"example/service@1a2b3c4"}],"attrs":{},"tags":[]},
 {"record_id":"01DAY1","received_at":"2026-08-26T09:20:43Z","action":"answer","outcome":"partial",
  "agent":"main_bot","entities":[{"kind":"ticket","id":"PROJ-42"}],"attrs":{},"tags":[]}],
 "token_estimate":40}
JSON
  exit 0
fi
case " $* " in
  *" --actor "*)
    cat <<'JSON'
{"records":[
 {"record_id":"01BG1","received_at":"2026-08-27T00:00:00Z","action":"answer","outcome":"ok",
  "agent":"the_writer","entities":[],"attrs":{"channel":"webchat"},"tags":[]},
 {"record_id":"01BG2","received_at":"2026-08-26T00:00:00Z","action":"check","outcome":"ok",
  "agent":"the_writer","entities":[],"attrs":{},"tags":[]},
 {"record_id":"01BG3","received_at":"2026-08-25T00:00:00Z","action":"verify","outcome":"ok",
  "agent":"the_writer","entities":[],"attrs":{},"tags":[]}],
 "degraded":true,"omitted":["actor the_writer: 1 record(s) over the bundle cap of 2"],
 "token_estimate":30}
JSON
    ;;
  *"--entity="*)
    cat <<'JSON'
{"records":[
 {"record_id":"01ANS1","received_at":"2026-08-24T00:00:00Z","action":"note","outcome":"ok",
  "agent":"someone_else","entities":[{"kind":"chat_thread","id":"c0example/1700000000.000100"}],
  "attrs":{},"tags":[]},
 {"record_id":"01ANS2","received_at":"2026-08-23T00:00:00Z","action":"note","outcome":"ok",
  "agent":"someone_else","entities":[{"kind":"chat_thread","id":"c0example/1700000000.000100"}],
  "attrs":{},"tags":[]}],
 "degraded":false,"omitted":[],"token_estimate":25}
JSON
    ;;
  *) printf '{"records":[],"degraded":false,"omitted":[],"token_estimate":0}' ;;
esac
STUB
cat > "$(reader garbage)" <<'STUB'
#!/usr/bin/env bash
printf 'not json at all'
STUB
cat > "$(reader slow)" <<'STUB'
#!/usr/bin/env bash
sleep 30
STUB
# The reader for a page that is exactly as long as it was allowed to be. It answers `--limit N` with
# N rows whatever N is, which is what a store with more rows than the page does -- and what neither
# the `search` nor the `records` read says anything about. A plugin that asks for only what it will
# show gets a full page here and cannot tell it from a complete answer.
#
# The bundle branch answers empty, so the search fallback is what fires and the digest keeps its turn.
cat > "$(reader over)" <<'STUB'
#!/usr/bin/env bash
[ -n "${READER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$READER_ARGS_FILE"
if [ "${1:-}" = "bundle" ]; then
  printf '{"records":[],"degraded":false,"omitted":[],"token_estimate":0}'
  exit 0
fi
limit=1
prev=""
for arg in "$@"; do
  [ "$prev" = "--limit" ] && limit="$arg"
  prev="$arg"
done
rows=""
i=0
while [ "$i" -lt "$limit" ]; do
  [ -n "$rows" ] && rows="$rows,"
  day=$((i % 2 + 1))
  rows="$rows{\"record_id\":\"01ROW$i\",\"received_at\":\"2026-08-0${day}T00:00:0${i}Z\",\"action\":\"note\",\"outcome\":\"ok\",\"agent\":\"someone\",\"entities\":[],\"attrs\":{},\"tags\":[]}"
  i=$((i + 1))
done
printf '{"records":[%s],"token_estimate":40}' "$rows"
STUB
chmod +x "$memwork"/bin/reader-*

# Stand-ins for the record tool, one per answer it can give. Each records the argv it was handed:
# what goes on that line -- and what never does -- is the whole subject guarantee.
emitter() { echo "$memwork/bin/emitter-$1"; }
cat > "$(emitter ok)" <<'STUB'
#!/usr/bin/env bash
[ -n "${EMITTER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$EMITTER_ARGS_FILE"
exit 0
STUB
# Exit 7 is a success: the sidecar holds the record and is still delivering it. A hook that read this
# as a failure would report an outage every time one was ridden out.
cat > "$(emitter spooled)" <<'STUB'
#!/usr/bin/env bash
[ -n "${EMITTER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$EMITTER_ARGS_FILE"
echo "the sidecar holds this record and is still delivering it" >&2
exit 7
STUB
cat > "$(emitter refused)" <<'STUB'
#!/usr/bin/env bash
[ -n "${EMITTER_ARGS_FILE:-}" ] && printf '%s\n' "$*" >> "$EMITTER_ARGS_FILE"
echo "the service refused this record (400): action not declared" >&2
exit 8
STUB
cat > "$(emitter slow)" <<'STUB'
#!/usr/bin/env bash
sleep 30
STUB
chmod +x "$memwork"/bin/emitter-*

echo "→ the recall installer refuses a read tool that is not there"
set +e
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$memwork/bin/absent" \
  >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the recall installer wired a reader that does not exist"

echo "→ the recall installer refuses a target that is not there"
set +e
"$ocmem" --config "$memwork/state/absent.json" --plugin-dir "$memwork/plug" \
  --reader "$(reader records)" >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the recall installer succeeded with no config to merge into"

echo "→ installing beside a config it must not touch"
membefore="$(cat "$memconfig")"
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --socket "$memwork/state/main.read.sock" --agent main >/dev/null
memfragment="$memwork/plug/config-fragment.json"
[ -f "$memfragment" ] || fail "no recall fragment was written"
for file in index.mjs openclaw.plugin.json package.json; do
  [ -f "$memwork/plug/$file" ] || fail "the recall plugin is missing $file"
done
[ "$(cat "$memconfig")" = "$membefore" ] || fail "the recall installer edited the live config"

echo "→ the fragment names the slot, and names it exclusively"
python3 - "$memfragment" "$memwork/plug" "$(reader records)" <<'PY' || status=1
import json, sys
fragment, plugin_dir, reader = sys.argv[1], sys.argv[2], sys.argv[3]
config = json.load(open(fragment))
problems = []
plugins = config.get("plugins", {})

if plugins.get("slots", {}).get("memory") != "harness-memory":
    problems.append(f"the memory slot is {plugins.get('slots')!r}, so the built-in still fills it")
if plugins.get("load", {}).get("paths") != [plugin_dir]:
    problems.append(f"load paths are {plugins.get('load')!r}, not where the plugin was installed")

entry = plugins.get("entries", {}).get("harness-memory")
if not entry:
    problems.append("the recall plugin has no entry, so it is installed and not enabled")
else:
    if entry.get("enabled") is not True:
        problems.append("the recall plugin entry is not enabled")
    argv = entry.get("config", {}).get("read")
    if not isinstance(argv, list) or not argv:
        problems.append(f"the reader is {argv!r}, not an argv the plugin can spawn")
    else:
        if argv[0] != reader:
            problems.append(f"the reader argv does not name the read tool: {argv}")
        # One read shape is wired, and the plugin refuses any other. A fragment naming a different
        # one would install a plugin that recalls nothing on every turn.
        if "bundle" not in argv:
            problems.append(f"the reader argv names no bundle read: {argv}")
        if "--socket" not in argv:
            problems.append(f"the reader argv names no socket: {argv}")
    # What lets a bundle name the turn. Without a thread kind every turn asks about the actor alone,
    # which is the shape of empty answer this plugin was rewired to stop producing.
    if not entry.get("config", {}).get("threadEntity"):
        problems.append("no threadEntity, so a turn in a thread asks about nothing but its actor")
    # And the spec directory is off unless asked for: this script cannot guess where one lives, and
    # an invented path would make every turn spend a lookup on a read the reader refuses.
    if "specDir" in entry.get("config", {}):
        problems.append("a specDir was wired that nobody asked for")
    # And the actor map, for a stronger reason than either: the writer names are the deployment's
    # keyring's, so a map this script invented would send a `--actor` naming a writer that may never
    # have written anything — which returns the same empty page a quiet store returns. Off unless
    # somebody who can read the keyring says otherwise.
    if "actors" in entry.get("config", {}):
        problems.append("an actor map was wired that nobody asked for")
    # Same rule for the digest, and a stronger reason: the other two settings only widen a lookup
    # the turn was making anyway, where a digest is a block of tokens nobody asked for. Off unless
    # an operator who can see the store says otherwise.
    if "digestDays" in entry.get("config", {}):
        problems.append("a session-opening digest was wired that nobody asked for")
    # And recording, for a third reason again: an action a store never declared is a rejected write
    # on every turn, and a recorder belonging to one agent signs another agent's turns as it.
    for key in ("recordAction", "record"):
        if key in entry.get("config", {}):
            problems.append(f"turns were wired to be recorded that nobody asked for: {key}")
    budget = entry.get("config", {}).get("timeoutMs")
    host = entry.get("hooks", {}).get("timeouts", {}).get("before_prompt_build")
    if not isinstance(budget, int) or not isinstance(host, int):
        problems.append(f"the lookup is unbounded: plugin={budget!r} host={host!r}")
    elif host <= budget:
        problems.append("the host would time out first, and its message says only that a hook failed")
    # Both of this plugin's hooks see a turn, which the harness classes as conversation access: a
    # plugin it did not ship may register one only where this says so. Without it the hooks are
    # refused at registration and the plugin loads, says nothing, and recalls nothing.
    if entry.get("hooks", {}).get("allowConversationAccess") is not True:
        problems.append("the hooks that see a turn are not granted, so the host refuses to register them")

# Two things owning memory is worse than either. The slot disables the built-in backend; the recall
# sub-agent is a separate plugin and has to be turned off by name.
if plugins.get("entries", {}).get("active-memory", {}).get("enabled") is not False:
    problems.append("the built-in recall sub-agent is left on, so two things inject memory")

for problem in problems:
    print(f"::error::generated fragment: {problem}")
sys.exit(1 if problems else 0)
PY

echo "→ the recall installer refuses a spec directory that is not one"
set +e
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --spec-dir "$memwork/bin" >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the recall installer wired a spec directory holding no entity rules"

echo "→ a spec directory that is one reaches the config the plugin reads"
mkdir -p "$memwork/spec"
printf 'version: 1\nkinds: {}\n' > "$memwork/spec/entities.yaml"
printf 'version: 1\ndefaults:\n  window: 4\n  confidence: 0.7\nkinds: {}\n' \
  > "$memwork/spec/extractors.yaml"
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --socket "$memwork/state/main.read.sock" --agent main --spec-dir "$memwork/spec" \
  --thread-kind chat_thread --digest-days 14 --actors 'main=main_bot,pr=pr_bot' >/dev/null
python3 - "$memfragment" "$memwork/spec" <<'TURNCFG' || status=1
import json, sys
config = json.load(open(sys.argv[1]))["plugins"]["entries"]["harness-memory"]["config"]
# The map reaches the config as a map, keyed by agent id and valued by the writer name. The plugin
# sends the value and never the key: sending the key is the defect the whole setting replaces.
if config.get("actors") != {"main": "main_bot", "pr": "pr_bot"}:
    print(f"::error::generated fragment: actors is {config.get('actors')!r}")
    sys.exit(1)
if config.get("specDir") != sys.argv[2]:
    print(f"::error::generated fragment: specDir is {config.get('specDir')!r}")
    sys.exit(1)
if config.get("threadEntity") != "chat_thread":
    print(f"::error::generated fragment: threadEntity is {config.get('threadEntity')!r}")
    sys.exit(1)
# The window and its two caps travel together: caps with no window read as a configured digest that
# never fires, which is the shape of wiring nobody thinks to debug.
if config.get("digestDays") != 14:
    print(f"::error::generated fragment: digestDays is {config.get('digestDays')!r}")
    sys.exit(1)
for cap in ("digestMaxRecords", "digestMaxChars"):
    if not isinstance(config.get(cap), int) or config[cap] <= 0:
        print(f"::error::generated fragment: the digest is uncapped: {cap}={config.get(cap)!r}")
        sys.exit(1)
# And it must not be able to spend the recall budget: a block nobody asked for that pushed out the
# answer to the question that was asked would be a worse turn than no digest at all.
if config["digestMaxChars"] > config["maxChars"]:
    print(f"::error::generated fragment: the digest may outgrow recall's own ceiling")
    sys.exit(1)
TURNCFG

echo "→ every setting the fragment writes is one the plugin's manifest declares"
# The host validates a plugin entry's config against `configSchema`, which is `additionalProperties:
# false`. A setting the installer emits and the manifest does not declare is not a setting that falls
# back to a default — it is a config the gateway refuses to load, and the installer's own fragment
# becomes the thing that breaks the deployment. Checked here rather than on a live host, which is
# where it was caught the first time.
python3 - "$memfragment" "$memwork/plug/openclaw.plugin.json" <<'DECLARED' || status=1
import json, sys
config = json.load(open(sys.argv[1]))["plugins"]["entries"]["harness-memory"]["config"]
schema = json.load(open(sys.argv[2])).get("configSchema", {})
if schema.get("additionalProperties") is not False:
    print("::error::the manifest's configSchema accepts anything, so it validates nothing")
    sys.exit(1)
undeclared = sorted(set(config) - set(schema.get("properties", {})))
if undeclared:
    print(f"::error::the fragment writes settings the manifest does not declare: {undeclared}")
    sys.exit(1)
DECLARED

echo "→ the recall installer refuses an actor map that does not parse"
# A map with a typo in it reaches the plugin as an agent it does not name, which asks about no actor
# on every turn — the same silence the setting exists to end, restored by a comma. Refused here, and
# a writer that would be read as a flag is refused for the second reason: it goes into an argv.
for bad in main 'main=' '=main_bot' 'main=-x' 'main=a,main=b' 'main=a b'; do
  set +e
  "$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
    --actors "$bad" >/dev/null 2>&1
  code=$?
  set -e
  [ "$code" -ne 0 ] || fail "the recall installer wired --actors '$bad'"
done

echo "→ the recall installer refuses a digest window that is not a number of days"
for bad in 0 -3 fortnight; do
  set +e
  "$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
    --digest-days "$bad" >/dev/null 2>&1
  code=$?
  set -e
  [ "$code" -ne 0 ] || fail "the recall installer wired --digest-days $bad, which the plugin reads as off"
done
echo "→ the recall installer refuses an actor page that is not a share of one"
# The actor is background: an allowance that is the whole page is the shape the fix exists to end,
# and `-1` or `half` reach the config as a value the plugin reads as unset -- an allowance that looks
# configured and silently is not. Zero is a real setting and is accepted.
for bad in 9 -1 half; do
  set +e
  "$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
    --actor-rows "$bad" >/dev/null 2>&1
  code=$?
  set -e
  [ "$code" -ne 0 ] || fail "the recall installer wired --actor-rows $bad"
done
set +e
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --actors main=main_bot --actor-rows 0 >/dev/null 2>&1
code=$?
set -e
[ "$code" -eq 0 ] || fail "the recall installer refused --actor-rows 0, which is a deployment wanting none"
grep -q '"actorMaxRecords": 0' "$memwork/plug/config-fragment.json" \
  || fail "--actor-rows 0 did not reach the config as zero"

# Put the fragment back to what the rest of this section asserts about.
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --socket "$memwork/state/main.read.sock" --agent main >/dev/null

echo "→ the recall installer refuses half a write path, and a recorder that is not there"
# An action with no recorder writes nowhere and looks wired; recorders with no action would write an
# action the store never declared, which is a rejected write on every turn rather than a quiet one.
# And a recorder that is not on disk would be wired anyway and fail on every turn -- quietly enough
# that a deployment could believe it had write coverage, which is the state this feature exists to end.
for half in "--record-action answer" "--recorders main=$(emitter ok)"; do
  set +e
  # shellcheck disable=SC2086
  "$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
    $half >/dev/null 2>&1
  code=$?
  set -e
  [ "$code" -ne 0 ] || fail "the recall installer wired half a write path: $half"
done
for bad in "main=$memwork/bin/emitter-absent" "main=-x" "=$(emitter ok)" "main" \
           "main=$(emitter ok),main=$(emitter ok)"; do
  set +e
  "$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
    --record-action answer --recorders "$bad" >/dev/null 2>&1
  code=$?
  set -e
  [ "$code" -ne 0 ] || fail "the recall installer wired --recorders $bad"
done
# The two maps know their own keys, so a misspelling is refused here rather than ignored by the
# plugin with nothing saying so.
for bad in "channel=channel,verdict=v" "recalled=" "channel"; do
  set +e
  "$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
    --record-action answer --recorders "main=$(emitter ok)" --record-attrs "$bad" >/dev/null 2>&1
  code=$?
  set -e
  [ "$code" -ne 0 ] || fail "the recall installer wired --record-attrs $bad"
done
set +e
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --record-action answer --recorders "main=$(emitter ok)" --record-outcomes "outcome=x" >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the recall installer wired an outcome key the plugin does not know"

echo "→ and the write path it does wire reaches the config as one piece"
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --socket "$memwork/state/main.read.sock" --agent main --thread-kind chat_thread \
  --record-action answer --recorders "main=$(emitter ok)" \
  --record-outcomes 'success=success,failure=' --record-attrs 'channel=channel,recalled=recalled' \
  >/dev/null
python3 - "$memfragment" "$(emitter ok)" <<'RECCFG' || status=1
import json, sys
entry = json.load(open(sys.argv[1]))["plugins"]["entries"]["harness-memory"]
config = entry["config"]
problems = []
if config.get("recordAction") != "answer":
    problems.append(f"recordAction is {config.get('recordAction')!r}")
# Keyed by agent id, valued by an argv: a record carries whatever caller its socket signed as, so
# one recorder for every agent would file each agent's turns under whichever writer that one signs as.
if config.get("record") != {"main": [sys.argv[2]]}:
    problems.append(f"record is {config.get('record')!r}, not one argv per agent")
# An empty spelling is a deployment saying its action has no word for that outcome, so those turns
# are not recorded at all. It has to survive as an empty string: dropped, it would read as "use the
# default", which files a failed turn under a word the store refuses.
if config.get("recordOutcomes") != {"success": "success", "failure": ""}:
    problems.append(f"recordOutcomes is {config.get('recordOutcomes')!r}")
if config.get("recordAttrs") != {"channel": "channel", "recalled": "recalled"}:
    problems.append(f"recordAttrs is {config.get('recordAttrs')!r}")
# Bounded twice over, like the lookup, and for the same reason: the answer that lands should name the
# recorder rather than say only that a hook failed.
budget = config.get("recordTimeoutMs")
host = entry.get("hooks", {}).get("timeouts", {}).get("agent_end")
if not isinstance(budget, int) or not isinstance(host, int):
    problems.append(f"the record write is unbounded: plugin={budget!r} host={host!r}")
elif host <= budget:
    problems.append("the host would time out the record write first")
for problem in problems:
    print(f"::error::generated fragment: {problem}")
sys.exit(1 if problems else 0)
RECCFG

# Put the fragment back to what the rest of this section asserts about.
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --socket "$memwork/state/main.read.sock" --agent main >/dev/null

echo "→ a second run changes nothing"
memdigest="$(cat "$memfragment" "$memwork/plug/index.mjs" | cksum)"
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --socket "$memwork/state/main.read.sock" --agent main >/dev/null
[ "$(cat "$memfragment" "$memwork/plug/index.mjs" | cksum)" = "$memdigest" ] \
  || fail "a second recall install rewrote the plugin or the fragment differently"
[ "$(cat "$memconfig")" = "$membefore" ] || fail "a second recall install edited the live config"

echo "→ it will not overwrite somebody else's plugin directory"
memother="$memwork/other"
mkdir -p "$memother"
printf '{"id":"some-other-plugin"}\n' > "$memother/openclaw.plugin.json"
set +e
"$ocmem" --config "$memconfig" --plugin-dir "$memother" --reader "$(reader records)" >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "the recall installer overwrote a directory holding another plugin"
grep -q 'some-other-plugin' "$memother/openclaw.plugin.json" \
  || fail "the other plugin's manifest was replaced"

echo "→ --apply refuses to drop the load path the guard plugin lives on"
set +e
"$ocmem" --config "$memconfig" --plugin-dir "$memwork/plug" --reader "$(reader records)" \
  --openclaw "$stub/openclaw" --apply >/dev/null 2>&1
code=$?
set -e
[ "$code" -ne 0 ] || fail "--apply would have replaced an existing plugins.load.paths"

echo "→ recall fails open, and says which kind of nothing it got"
if command -v node >/dev/null 2>&1; then
  # Written out rather than inlined because it is run several times: once against the plugin, then
  # once against each mutant, to check these assertions can actually fail.
  cat > "$work/recall-assertions.mjs" <<'JS'
// Exercises the recall path without a gateway around it. argv[2] is the module under test, argv[3]
// the directory holding the stand-in readers.
const [, , modulePath, binDir] = process.argv;
const mod = await import(modulePath);
const { recall, renderContext, injectionFrom, report, bounds, actorFor, actorPlan, turnOf, threadOf, HEADING,
        MAX_INFER_CHARS, needleFrom, searchArgv, SEARCH_SHAPE, SEARCH_HEADING, READ_SHAPE,
        actorAllowance, withoutActor, actorWriterIn, DEFAULT_ACTOR_MAX_RECORDS,
        claimOpening, DIGEST_HEADING, SEEN_SESSIONS,
        TRUNCATED_NOTE, DIGEST_TRUNCATED_NOTE, OVER_READ,
        recordTurn, reportRecord, unwritable, recordedDuring, RECORD_SUMMARY } = mod;

const problems = [];
const reader = (name, ...rest) => [`${binDir}/reader-${name}`, "bundle", ...rest];
const recorder = () => {
  const lines = [];
  return { lines, info: (m) => lines.push(["info", String(m)]), warn: (m) => lines.push(["warn", String(m)]) };
};
const said = (log, level) => log.lines.filter(([at]) => at === level).map(([, m]) => m).join("\n");

// A lookup that found something reaches the injection point, as structure and not as prose.
const found = await recall({ read: reader("records") }, { agentId: "builder" });
const injected = injectionFrom(found);
if (found.kind !== "recalled") problems.push(`a bundle with records gave ${found.kind}: ${found.why ?? ""}`);
if (!injected?.prependContext) problems.push("a bundle with records injected nothing");
else {
  const text = injected.prependContext;
  if (!text.startsWith(HEADING)) problems.push("the injected block does not say what it is");
  for (const expected of ["action=deploy", "outcome=ok", "service:api", "env=staging", "action=review"]) {
    if (!text.includes(expected)) problems.push(`the injected block dropped ${expected}`);
  }
}

// An empty match: no context, and a line saying the store was quiet rather than broken.
const emptyLog = recorder();
const empty = await recall({ read: reader("empty") }, { agentId: "builder" });
report(empty, emptyLog);
if (empty.kind !== "empty") problems.push(`an empty bundle gave ${empty.kind}`);
if (injectionFrom(empty) !== undefined) problems.push("an empty bundle injected something");
if (!/matched nothing/.test(said(emptyLog, "info"))) problems.push("an empty match was not reported as one");
if (said(emptyLog, "warn")) problems.push(`an empty match warned: ${said(emptyLog, "warn")}`);

// Every way a lookup can fail to answer: the turn proceeds, and the log says the plumbing failed.
for (const [label, settings] of [
  ["no reader configured", {}],
  ["a reader that is not there", { read: reader("absent") }],
  ["a read shape this does not inject", { read: [`${binDir}/reader-records`, "records"] }],
  ["a refused read", { read: reader("refused") }],
  ["an unreadable answer", { read: reader("garbage") }],
  ["a reader that never answered", { read: reader("slow"), timeoutMs: 200 }],
]) {
  const log = recorder();
  const outcome = await recall(settings, { agentId: "builder" });
  report(outcome, log);
  if (outcome.kind !== "unavailable") problems.push(`${label} gave ${outcome.kind}, not unavailable`);
  if (injectionFrom(outcome) !== undefined) problems.push(`${label} injected context`);
  if (!/recall unavailable/.test(said(log, "warn"))) problems.push(`${label} was not warned about`);
  if (/matched nothing/.test(said(log, "info"))) problems.push(`${label} was reported as an empty match`);
  if (!outcome.why) problems.push(`${label} gave no reason`);
}

// A partial bundle is safe to answer from and unsafe to act on, so it has to say so.
const partial = await recall({ read: reader("degraded") }, { agentId: "builder" });
if (partial.kind !== "recalled" || !partial.degraded) problems.push("a degraded bundle did not report itself");
if (!/partial/i.test(injectionFrom(partial)?.prependContext ?? "")) {
  problems.push("a degraded bundle injected a block that reads as complete");
}

// A capped list must not read as the whole truth.
const capped = renderContext(
  { records: [{ action: "a" }, { action: "b" }, { action: "c" }], degraded: false },
  { maxRecords: 1, maxChars: 4096 },
);
if (!/2 further record/.test(capped)) problems.push("a capped list did not say what it left out");

// The bounds the plugin adds, and the actor the host supplied, reach the process it spawns -- and
// they reach *different* processes. The turn's own question and the actor's background page are two
// reads now, because one read with one `--limit` cannot bound two sources separately: the service
// fills entities first and hands the actor the rest, so the actor's share was whatever the keys left.
const argsFile = `${binDir}/../args`;
process.env.READER_ARGS_FILE = argsFile;
await recall(
  { read: reader("background"), threadEntity: "chat_thread", timeoutMs: 4000, maxRecords: 3,
    actors: { builder: "builder_bot" } },
  turnOf({ threadEntity: "chat_thread" }, { prompt: "any news on this?" },
    { agentId: "builder", channelId: "c0example:thread:1700000000.000100" }),
);
delete process.env.READER_ARGS_FILE;
const passed = (await import("node:fs")).readFileSync(argsFile, "utf8");
const reads = passed.trim().split("\n");
// The actor that reaches the reader is the *writer name* the map gave, never the agent id the host
// supplied. Sending the id is the defect this whole mechanism replaces.
for (const expected of ["--limit 3", "--deadline-ms 2000", "--timeout-ms 3200", "--actor builder_bot"]) {
  if (!passed.includes(expected)) problems.push(`the reader was not given ${expected}: ${passed.trim()}`);
}
if (passed.includes("--actor builder ")) problems.push(`the agent id was passed as an actor: ${passed.trim()}`);
if (reads.length !== 2) problems.push(`the answer and the actor's page were not two reads: ${reads.join(" | ")}`);
else {
  const [answering, background] = reads;
  // **The read that answers the turn carries no actor.** This is the whole of the fix: with the
  // actor on this read the service gives it whatever the entities left, which on a turn naming no
  // key is the entire page -- the same rows for a greeting, a prose question and a generic one.
  if (answering.includes("--actor")) {
    problems.push(`the read that answers the turn carried an actor: ${answering}`);
  }
  if (!answering.includes("--entity=chat_thread:c0example/1700000000.000100")) {
    problems.push(`the answering read lost the turn's own key: ${answering}`);
  }
  // And the actor's read asks for its allowance and nothing else, so it *cannot* overflow the page:
  // two entity records out of a page of three leaves one row, and one row is what it asks for.
  if (!background.includes("--limit 1")) {
    problems.push(`the actor's read was not bounded to its allowance: ${background}`);
  }
  if (background.includes("--entity") || background.includes("--infer-from")) {
    problems.push(`the actor's read was narrowed to the turn's keys, which the answer already asked: ${background}`);
  }
}
// The allowance itself: never more than the setting, never more than the page has left, and *zero*
// where the entities matched nothing -- there is no answer there for background to be background to.
const page8 = { maxRecords: 8, maxChars: 4096 };
if (actorAllowance({}, page8, 0) !== 0) problems.push("a turn whose entities matched nothing was still offered an actor page");
if (actorAllowance({}, page8, 2) !== DEFAULT_ACTOR_MAX_RECORDS) problems.push("a thin answer was not offered the full allowance");
if (actorAllowance({}, page8, 7) !== 1) problems.push("the actor was offered more of the page than the entities left");
if (actorAllowance({}, page8, 8) !== 0) problems.push("a full page still offered the actor a row");
if (actorAllowance({ actorMaxRecords: 0 }, page8, 2) !== 0) {
  problems.push("actorMaxRecords: 0 was read as unset rather than as none");
}
if (actorAllowance({ actorMaxRecords: 5 }, page8, 2) !== 5) problems.push("a configured allowance was ignored");
// An operator's own `--actor` in the argv keeps its writer and loses its place on the answering read:
// which writer is theirs, how much of the page it gets is not.
if (actorWriterIn(["r", "bundle", "--actor", "other"]) !== "other") problems.push("an operator's writer was not read off the argv");
if (actorWriterIn(["r", "bundle", "--actor=other"]) !== "other") problems.push("an operator's writer in the joined spelling was not read");
if (withoutActor(["r", "bundle", "--actor", "other", "--socket", "s"]).join(" ") !== "r bundle --socket s") {
  problems.push(`the actor was not taken off the answering read: ${withoutActor(["r", "bundle", "--actor", "other", "--socket", "s"]).join(" ")}`);
}
// A bound an operator already chose is theirs, not this file's to replace.
if (bounds(["r", "bundle", "--limit", "1"], 5000, 8).includes("--limit")) {
  problems.push("a configured --limit was overridden");
}
if (actorFor(["r", "bundle", "--actor", "other"], { agentId: "builder" }).length !== 0) {
  problems.push("a configured --actor was overridden");
}
// An agent id that would be read as a flag is not passed as one.
if (actorFor(["r", "bundle"], "--actor").length !== 0) problems.push("an agent id shaped like a flag was passed");

// ── An agent id is not a writer name ─────────────────────────────────────────────────────────────
// The defect that made half of recall dead on arrival: `ctx.agentId` went straight to `--actor`, and
// every record in the live store was written by a *writer* the keyring named separately. Measured on
// that store: `--actor main` 0 records, `--actor main_bot` 8. So the actor half never matched
// anything, and an empty page is exactly what a quiet store returns -- the failure had no symptom.
//
// The mechanism is a map somebody wrote down, because the two that could be derived both invent: a
// `_bot` suffix promotes one deployment's convention to a fact, and the socket path in `config.read`
// names one writer for every agent on a host where one read socket serves all three.
const mapped = { main: "main_bot", pr: "pr_bot" };
if (actorFor(["r", "bundle"], "main", mapped).join(" ") !== "--actor main_bot") {
  problems.push(`a mapped agent did not ask about its writer: ${actorFor(["r", "bundle"], "main", mapped).join(" ")}`);
}
// **An agent the map does not name asks about no actor.** This is the decision, and it is the whole
// fix: passing the id is what produced the silent zero, and omitting the flag asks a narrower
// question honestly.
for (const [label, id, map] of [
  ["an agent the map does not name", "deploy", mapped],
  ["an agent on a deployment with no map at all", "main", undefined],
  ["a map that is not a map", "main", "main_bot"],
  ["a writer that would be read as a flag", "main", { main: "--sneaky" }],
  ["a writer named as nothing", "main", { main: "   " }],
  ["a writer that is not a string", "main", { main: 7 }],
]) {
  const got = actorFor(["r", "bundle"], id, map);
  if (got.length !== 0) problems.push(`${label} still asked about one: ${got.join(" ")}`);
  if (actorPlan(["r", "bundle"], id, map).kind !== "unmapped") {
    problems.push(`${label} was not reported as unmapped: ${JSON.stringify(actorPlan(["r", "bundle"], id, map))}`);
  }
}
// The other three plans, told apart by name rather than by an absent argv, because "the operator
// named one", "nothing named one" and "no agent id arrived" call for different words in the log.
if (actorPlan(["r", "bundle", "--actor", "other"], "main", mapped).kind !== "configured") {
  problems.push("an operator's own --actor was not left alone");
}
if (actorPlan(["r", "bundle"], undefined, mapped).kind !== "unnamed") problems.push("a turn with no agent id read as unmapped");
if (actorPlan(["r", "bundle"], "main", mapped).kind !== "named") problems.push("a mapped agent was not reported as named");

// ── The actor is background, and the page says where the answer stops ────────────────────────────
// End to end against a reader that tells the two reads apart. The entities answer; the actor's page
// is appended behind them, bounded, labelled, and **not counted as a partiality of the answer**.
//
// That last clause is the second regression the map above caused. `--limit N` reads N+1 rows so that
// "there is more" is a fact rather than a guess, so an actor with more history than its share always
// reports itself degraded -- and while the actor rode the answer's read, every keyless turn on the
// live deployment ended `This is partial: actor main_bot: N record(s) over the bundle cap of 8 ...
// not safe to act on`. For ever, because that agent's history outruns any page and always will. A
// warning that is always on is a warning nobody reads, and this one sits on the sentence telling a
// model what it may act on.
const actorWired = { threadEntity: "chat_thread", read: reader("background"), actors: { main: "main_bot" } };
const actorTurn = turnOf(actorWired, { prompt: "any news on this?" },
  { agentId: "main", channelId: "c0example:thread:1700000000.000100" });
const hit = await recall(actorWired, actorTurn);
if (hit.kind !== "recalled") problems.push(`a mapped actor recalled nothing: ${hit.kind} ${hit.why ?? ""}`);
if (hit.actor?.kind !== "named" || hit.actor.writer !== "main_bot") {
  problems.push(`the outcome did not name the actor it asked about: ${JSON.stringify(hit.actor)}`);
}
if (hit.via !== READ_SHAPE) problems.push(`a bundle that answered did not say so: ${hit.via}`);
// **The actor's overflow is not the answer's partiality.** The fixture's actor page is `degraded`
// and says so in `omitted`; the answer's own read is not, and the block must not read as one.
if (hit.degraded !== false) problems.push("the actor overflowing its allowance was reported as a partial answer");
if (/This is partial/.test(hit.context)) {
  problems.push(`a complete answer was labelled partial because the actor has more history: ${hit.context}`);
}
if (/not safe to act on/.test(hit.context)) problems.push("the act-on warning fired for a background source");
// Bounded: the actor gets its allowance out of what the entities left, and no more, whatever the
// reader hands back. The fixture returns three rows for a page that had two to spare.
if (hit.background?.shown !== DEFAULT_ACTOR_MAX_RECORDS) {
  problems.push(`the actor's page was not held to its allowance: ${JSON.stringify(hit.background)}`);
}
if (hit.count !== 4) problems.push(`the page was not two answers plus two background rows: ${hit.count}`);
if (hit.context.includes("01BG3") || hit.context.split("action=").length - 1 !== 4) {
  problems.push(`the actor's read overflowed the page: ${hit.context}`);
}
// Labelled: two claims in one block, and the block says where one ends. Silently dropping the
// distinction is the other way to be dishonest about a source that was cut.
if (!hit.context.includes(`The last 2 row(s) are main_bot's own recent activity`)) {
  problems.push(`the background rows were not told apart from the answer: ${hit.context}`);
}
if (!/there is more of it than is shown/.test(hit.context)) {
  problems.push(`a cut background page did not say it was cut: ${hit.context}`);
}
// And in order: what the keys answered comes first, so a ceiling cuts the background rather than
// the answer.
if (hit.context.indexOf("01ANS2") > hit.context.indexOf("01BG1") && hit.context.includes("01ANS2")) {
  problems.push("the actor's page displaced the records the keys matched");
}
const hitLog = recorder();
report(hit, hitLog);
if (!/actor main_bot/.test(said(hitLog, "info"))) problems.push(`the log did not say whose activity answered: ${said(hitLog, "info")}`);
if (!/2 background row\(s\)/.test(said(hitLog, "info"))) {
  problems.push(`the log did not say how much of the page was background: ${said(hitLog, "info")}`);
}

// A deployment that wants none says so, and no second read is made at all.
const noneAsked = await (async () => {
  const file = `${binDir}/../no-background-args`;
  process.env.READER_ARGS_FILE = file;
  const outcome = await recall({ ...actorWired, actorMaxRecords: 0 }, actorTurn);
  delete process.env.READER_ARGS_FILE;
  return { outcome, asked: (await import("node:fs")).readFileSync(file, "utf8").trim().split("\n") };
})();
if (noneAsked.asked.length !== 1 || noneAsked.asked[0].includes("--actor")) {
  problems.push(`actorMaxRecords: 0 still read the actor's page: ${noneAsked.asked.join(" | ")}`);
}
if (noneAsked.outcome.background !== undefined) problems.push("a background page arrived with the allowance at zero");
// And a page the entities filled leaves nothing to spend, so the read is not made either.
const fullPage = await (async () => {
  const file = `${binDir}/../full-page-args`;
  process.env.READER_ARGS_FILE = file;
  const outcome = await recall({ ...actorWired, maxRecords: 2 }, actorTurn);
  delete process.env.READER_ARGS_FILE;
  return { outcome, asked: (await import("node:fs")).readFileSync(file, "utf8").trim().split("\n") };
})();
if (fullPage.asked.length !== 1) problems.push(`a full page still read the actor: ${fullPage.asked.join(" | ")}`);

const missFile = `${binDir}/../unmapped-args`;
process.env.READER_ARGS_FILE = missFile;
const miss = await recall({ ...actorWired, searchFallback: false }, { agentId: "deploy" });
delete process.env.READER_ARGS_FILE;
const missArgs = (await import("node:fs")).readFileSync(missFile, "utf8");
if (missArgs.includes("--actor")) problems.push(`an unmapped agent id was passed as an actor: ${missArgs.trim()}`);
if (miss.kind !== "empty") problems.push(`an unmapped agent gave ${miss.kind}, not an empty answer`);
if (miss.actor?.kind !== "unmapped" || miss.actor.agentId !== "deploy") {
  problems.push(`the outcome did not say the agent was unmapped: ${JSON.stringify(miss.actor)}`);
}
// And the log says which happened, at info and without a warning: the turn proceeds exactly as a turn
// with nothing to ask about always did, but nobody has to read the config to find out that is why.
const missLog = recorder();
report(miss, missLog);
const missSaid = said(missLog, "info");
if (!/no actor was asked about/.test(missSaid)) problems.push(`an unmapped agent was not reported: ${missSaid}`);
if (!/"deploy"/.test(missSaid)) problems.push(`the report did not name the unmapped agent: ${missSaid}`);
if (!/config\.actors/.test(missSaid)) problems.push(`the report did not name the setting that fixes it: ${missSaid}`);
if (said(missLog, "warn")) problems.push(`an unmapped agent warned: ${said(missLog, "warn")}`);
// A turn that never had an agent id is a different absence and is not reported as a missing map.
const anon = await recall({ ...actorWired, searchFallback: false }, {});
const anonLog = recorder();
report(anon, anonLog);
if (/no actor was asked about/.test(said(anonLog, "info"))) {
  problems.push(`a turn with no agent id was blamed on the map: ${said(anonLog, "info")}`);
}

// ── What a turn can tell a bundle about itself ────────────────────────────────────────────────────
// A bundle composes context out of entities and an actor. Asking about the actor alone is what left
// every turn empty, so what is checked here is that the two things the hook payload does carry — the
// conversation and the message — actually reach the read.

// The host spells a threaded run's conversation id with the thread inside it; a record joins on the
// two either side of a slash.
const wired = { threadEntity: "chat_thread", specDir: "/srv/memory/spec" };
if (threadOf("c0example:thread:1700000000.000100") !== "c0example/1700000000.000100") {
  problems.push(`a threaded conversation id did not become an entity: ${threadOf("c0example:thread:1700000000.000100")}`);
}
// Not in a thread is an absence, not a fault: nothing is invented for it.
for (const flat of ["c0example", "", ":thread:1700000000.000100", undefined]) {
  if (threadOf(flat) !== undefined) problems.push(`${JSON.stringify(flat)} was read as a thread`);
}

// The whole payload, as the harness hands it over: `event` carries the prompt, `ctx` the ids.
const threaded = turnOf(wired, { prompt: "  any news on this?  ", messages: [] }, {
  agentId: "main",
  channelId: "c0example:thread:1700000000.000100",
});
if (threaded.entities[0] !== "chat_thread:c0example/1700000000.000100") {
  problems.push(`the turn did not name its thread: ${JSON.stringify(threaded.entities)}`);
}
if (threaded.text !== "any news on this?") problems.push(`the message did not reach the turn: ${threaded.text}`);
if (threaded.agentId !== "main") problems.push("the actor was lost");

// The one that matters: a turn in a thread finds the record filed under that thread. The reader
// answers nothing for any other read, so this cannot pass by being answered anyway.
const recalled = await recall({ ...wired, read: reader("thread") }, threaded);
if (recalled.kind !== "recalled") {
  problems.push(`a turn in a thread recalled nothing: ${recalled.kind} ${recalled.why ?? ""}`);
} else if (!injectionFrom(recalled)?.prependContext.includes("chat_thread:c0example/1700000000.000100")) {
  problems.push("the recalled record did not come back as the thread's");
}

// A turn that is in no thread and says nothing that reads as one asks about the actor alone, and the
// empty answer that comes back is an empty answer — the turn proceeds, and nothing is injected.
const bare = turnOf(wired, { prompt: "", messages: [] }, { agentId: "main", channelId: "c0example" });
if (bare.entities.length !== 0 || bare.text !== undefined) problems.push("a bare turn invented something to ask about");
const bareLog = recorder();
const bareOutcome = await recall({ ...wired, read: reader("thread") }, bare);
report(bareOutcome, bareLog);
if (bareOutcome.kind !== "empty") problems.push(`a bare turn gave ${bareOutcome.kind}`);
if (injectionFrom(bareOutcome) !== undefined) problems.push("a bare turn injected something");
if (said(bareLog, "warn")) problems.push(`a bare turn warned: ${said(bareLog, "warn")}`);
// And the same turn against a reader that cannot answer still lets the turn through.
const brokenLog = recorder();
const broken = await recall({ ...wired, read: reader("absent") }, bare);
report(broken, brokenLog);
if (broken.kind !== "unavailable") problems.push(`a bare turn with no reader gave ${broken.kind}`);
if (injectionFrom(broken) !== undefined) problems.push("a failed bare turn injected something");
if (!/recall unavailable/.test(said(brokenLog, "warn"))) problems.push("a failed bare turn was not warned about");

// The message and the rules to read it with travel together, and never one without the other.
const inferFile = `${binDir}/../infer-args`;
process.env.READER_ARGS_FILE = inferFile;
await recall({ ...wired, read: reader("empty") }, turnOf(wired, { prompt: "closing ticket PROJ-42" }, {
  agentId: "main",
  channelId: "c0example:thread:1700000000.000100",
}));
delete process.env.READER_ARGS_FILE;
const inferred = (await import("node:fs")).readFileSync(inferFile, "utf8");
for (const expected of [
  "--entity=chat_thread:c0example/1700000000.000100",
  "--infer-entities=/srv/memory/spec",
  "--infer-from=closing ticket PROJ-42",
]) {
  if (!inferred.includes(expected)) problems.push(`the reader was not given ${expected}: ${inferred.trim()}`);
}
// No spec directory means no inference, rather than a flag the reader refuses for want of its pair.
const halfFile = `${binDir}/../half-args`;
process.env.READER_ARGS_FILE = halfFile;
await recall({ threadEntity: "chat_thread", read: reader("empty") },
  turnOf({ threadEntity: "chat_thread" }, { prompt: "closing ticket PROJ-42" }, { agentId: "main" }));
delete process.env.READER_ARGS_FILE;
const half = (await import("node:fs")).readFileSync(halfFile, "utf8");
for (const absent of ["--infer-entities", "--infer-from", "--entity"]) {
  if (half.includes(absent)) problems.push(`an unconfigured lookup still passed ${absent}: ${half.trim()}`);
}
// An entity kind the config never named is a vocabulary this harness does not get to invent.
if (turnOf({}, { prompt: "x" }, { channelId: "c0example:thread:1700000000.000100" }).entities.length !== 0) {
  problems.push("a thread was looked up under an entity kind nothing configured");
}
// A message longer than one argument may be keeps its end, which is where this turn is.
const long = turnOf(wired, { prompt: `${"x".repeat(MAX_INFER_CHARS * 2)} ticket PROJ-42` }, {});
if (long.text.length !== MAX_INFER_CHARS) problems.push(`a long message was not capped: ${long.text.length}`);
if (!long.text.endsWith("ticket PROJ-42")) problems.push("capping a long message dropped its end");
// Anything an operator wired by hand stays theirs.
const configured = await (async () => {
  const file = `${binDir}/../configured-args`;
  process.env.READER_ARGS_FILE = file;
  await recall({ ...wired, read: [`${binDir}/reader-empty`, "bundle", "--entity", "ticket:PROJ-9"] }, threaded);
  delete process.env.READER_ARGS_FILE;
  return (await import("node:fs")).readFileSync(file, "utf8");
})();
if (configured.includes("--entity=")) problems.push(`a configured --entity was added to: ${configured.trim()}`);

// --- the search fallback -----------------------------------------------------------------------
// A bundle that matched nothing asks a second, weaker question. These assertions are about keeping
// the two apart: what it asks, that it says which one answered, and that it can be switched off.
const fellBack = await (async () => {
  const file = `${binDir}/../fallback-args`;
  process.env.READER_ARGS_FILE = file;
  const outcome = await recall({ ...wired, read: reader("fallback") },
    turnOf(wired, { prompt: "any knowledge abou this? WUPGHGJ7ELJM626" }, {
      agentId: "main", channelId: "c0example:thread:1700000000.000100",
    }));
  delete process.env.READER_ARGS_FILE;
  const asked = (await import("node:fs")).readFileSync(file, "utf8").trim().split("\n");
  return { outcome, asked };
})();
if (fellBack.asked.length !== 2) {
  problems.push(`an empty bundle did not fall back to a search: ${fellBack.asked.join(" | ")}`);
} else {
  const [first, second] = fellBack.asked;
  if (!first.startsWith("bundle")) problems.push(`the first read was not the bundle: ${first}`);
  if (!second.startsWith("search")) problems.push(`the fallback was not the search shape: ${second}`);
  // The needle is what the first version got wrong: an unquoted question mark is a syntax error the
  // index refuses, so every term is quoted and the framing words are not terms at all.
  if (!second.includes('"WUPGHGJ7ELJM626"')) problems.push(`the needle lost the identifier: ${second}`);
  if (second.includes("?")) problems.push(`the needle carried punctuation the index will refuse: ${second}`);
  // The search read has no --deadline-ms; the bundle's bounds are not its bounds. A fake reader
  // accepts every flag, so this is asserted by name -- it is the one failure in this fallback that
  // shipped, and it made the fallback fail every single time while looking wired.
  if (second.includes("--deadline-ms")) {
    problems.push(`the fallback passed a bundle-only flag the search read refuses: ${second}`);
  }
  if (!second.includes("--limit")) problems.push(`the fallback was not bounded: ${second}`);
  for (const framing of ['"any"', '"knowledge"', '"this"']) {
    if (second.includes(framing)) problems.push(`the needle searched for a framing word ${framing}: ${second}`);
  }
}
// A search hit is a weaker claim than a composed bundle, and the block has to say so or a model
// presents a keyword match as an established connection.
if (fellBack.outcome?.kind !== "recalled") {
  problems.push(`the fallback did not recall: ${JSON.stringify(fellBack.outcome)}`);
} else {
  if (fellBack.outcome.via !== SEARCH_SHAPE) problems.push(`the outcome did not say it came from a search: ${fellBack.outcome.via}`);
  if (!fellBack.outcome.context.startsWith(SEARCH_HEADING)) {
    problems.push(`a search hit was injected under the bundle's heading: ${fellBack.outcome.context.slice(0, 80)}`);
  }
}
// Off is off, and an empty bundle stays an empty answer.
const noFallback = await (async () => {
  const file = `${binDir}/../nofallback-args`;
  process.env.READER_ARGS_FILE = file;
  const outcome = await recall({ ...wired, searchFallback: false, read: reader("empty") },
    turnOf(wired, { prompt: "any knowledge abou this? WUPGHGJ7ELJM626" }, { agentId: "main", channelId: "c0example" }));
  delete process.env.READER_ARGS_FILE;
  return { outcome, asked: (await import("node:fs")).readFileSync(file, "utf8").trim().split("\n") };
})();
if (noFallback.asked.length !== 1) problems.push(`searchFallback:false still searched: ${noFallback.asked.join(" | ")}`);
if (noFallback.outcome?.kind !== "empty") problems.push(`with the fallback off an empty bundle was not empty: ${noFallback.outcome?.kind}`);
// A question with no subject in it is not worth a second lookup.
if (needleFrom("do you remember anything about this?") !== undefined) {
  problems.push("a message of nothing but framing words produced a needle");
}
// The fallback reads the same store: same reader, same socket, one word different.
const swapped = searchArgv(["yaam-read", "bundle", "--socket", "/srv/x.sock"]);
if (swapped.join(" ") !== "yaam-read search --socket /srv/x.sock") {
  problems.push(`the fallback did not reuse the reader and socket: ${swapped.join(" ")}`);
}

// --- the host's envelope, and the calendar ---------------------------------------------------------
// `event.prompt` is not the message: this host prepends an RFC-1123 timestamp, and until it was taken
// off, every needle searched for the current date. Measured on the live store before the fix: the four
// terms one stamp contributes matched 36 of 73 records on their own, and a bare-identifier turn came
// back with 8 records of which 1 named the identifier. The fallback was ranking the calendar and
// reporting it as a hit, which is worse than returning nothing, because nothing is legible.
const STAMP = "Fri, 28 Aug 2026 15:16:51 GMT";
const stamped = turnOf(wired, { prompt: `${STAMP}\nany knowledge abou this? WUPGHGJ7ELJM626` },
  { agentId: "main" });
if (stamped.text !== "any knowledge abou this? WUPGHGJ7ELJM626") {
  problems.push(`the host's framing reached the turn as if a person had typed it: ${JSON.stringify(stamped.text)}`);
}
const stampedNeedle = needleFrom(stamped.text) ?? "";
// The case the fallback exists for. It has to survive every rule added above it.
if (!stampedNeedle.includes('"WUPGHGJ7ELJM626"')) {
  problems.push(`a stamped turn lost the identifier the fallback is for: ${stampedNeedle}`);
}
for (const dated of ['"Fri"', '"Aug"', '"2026"', '"GMT"']) {
  if (stampedNeedle.includes(dated)) problems.push(`the needle searched the calendar for ${dated}: ${stampedNeedle}`);
}
// And a date the person typed themselves, which no envelope strip can reach. Two rules, two reasons:
// one is about whose words these are, the other about what a word can distinguish.
const typed = needleFrom("what shipped on Fri 28 Aug 2026 GMT") ?? "";
for (const dated of ['"Fri"', '"Aug"', '"2026"', '"GMT"']) {
  if (typed.includes(dated)) problems.push(`a date somebody typed became a needle term ${dated}: ${typed}`);
}
// A turn that is nothing but the stamp asked nothing, and is not worth a second lookup.
if (needleFrom(turnOf(wired, { prompt: STAMP }, { agentId: "main" }).text) !== undefined) {
  problems.push("a prompt holding nothing but the host's stamp still produced a needle");
}
// An identifier is not a date, however lenient a date reader would be about it. `Date.parse` accepts
// `PROJ-2087` as a date in the year 2087, so a stripper built on one would throw away the one kind of
// line this fallback exists to read.
const kept = turnOf(wired, { prompt: "PROJ-2087\nwhat happened here" }, { agentId: "main" });
if (kept.text !== "PROJ-2087\nwhat happened here") {
  problems.push(`an identifier line was read as the host's framing: ${JSON.stringify(kept.text)}`);
}

// --- the session-opening digest ------------------------------------------------------------------
// The one thing here that is not about the turn. `before_prompt_build` fires every turn, so the whole
// feature rests on a fence: off unless configured, once per session, and never in front of a recall
// that had an answer. Each of those is asserted, and each has a mutant behind it, because a digest
// that quietly went to every-turn would look exactly like this one working.

const digestTurn = (session, messages) =>
  turnOf({ threadEntity: "chat_thread" }, { prompt: "", messages }, { agentId: "main", sessionKey: session });
const spawned = async (settings, turn) => {
  const file = `${binDir}/../digest-args-${Math.random().toString(36).slice(2)}`;
  process.env.READER_ARGS_FILE = file;
  const outcome = await recall(settings, turn);
  delete process.env.READER_ARGS_FILE;
  const raw = (await import("node:fs")).readFileSync(file, "utf8").trim();
  return { outcome, asked: raw ? raw.split("\n") : [] };
};
const digested = { threadEntity: "chat_thread", digestDays: 14 };

// The payload signal, on its own. `event.messages` is the session's prepared history, which the host
// passes beside the prompt rather than including this turn in — so an empty one is the opening turn.
SEEN_SESSIONS.clear();
if (claimOpening({ messages: [] }, { sessionKey: "s-unit" }) !== true) problems.push("an opening turn was not recognised");
if (claimOpening({ messages: [] }, { sessionKey: "s-unit" }) !== false) problems.push("the same session was offered a digest twice");
if (claimOpening({ messages: [{}] }, { sessionKey: "s-unit-2" }) !== false) problems.push("a turn with history behind it read as an opening");
// A turn this cannot tell apart from the next one is never an opening: injecting on it is the
// every-turn cost the fence exists to prevent.
if (claimOpening({ messages: [] }, {}) !== false) problems.push("a turn naming no session read as an opening");
if (claimOpening({ messages: undefined }, { sessionKey: "s-unit-3" }) !== false) problems.push("a payload with no history at all read as an opening");

// **Not on every turn.** The turn that opens the session gets one; the next turn in that session does
// not, and neither does a later turn whose history the host happens to hand over empty.
SEEN_SESSIONS.clear();
const first = await spawned({ ...digested, read: reader("digest") }, digestTurn("s-live", []));
if (!injectionFrom(first.outcome)?.prependContext?.includes(DIGEST_HEADING)) {
  problems.push(`the turn that opened a session got no digest: ${JSON.stringify(first.outcome)}`);
}
const second = await spawned({ ...digested, read: reader("digest") }, digestTurn("s-live", [{}]));
if (injectionFrom(second.outcome) !== undefined) problems.push("a second turn in the same session was given a digest");
if (second.asked.some((line) => line.startsWith("records"))) problems.push(`a second turn still read the window: ${second.asked.join(" | ")}`);
const third = await spawned({ ...digested, read: reader("digest") }, digestTurn("s-live", []));
if (injectionFrom(third.outcome) !== undefined) problems.push("a later turn with empty history was given a second digest");

// **Off unless configured**, and off means the window is never read at all.
SEEN_SESSIONS.clear();
const unasked = await spawned({ threadEntity: "chat_thread", read: reader("digest") }, digestTurn("s-off", []));
if (injectionFrom(unasked.outcome) !== undefined) problems.push("a digest was injected with no digestDays configured");
if (unasked.asked.some((line) => line.startsWith("records"))) problems.push(`an unconfigured digest still read the window: ${unasked.asked.join(" | ")}`);

// **An entity hit takes the turn.** It is the composed answer to the question that was asked, so the
// window is not even read and nothing unasked-for is appended to it.
SEEN_SESSIONS.clear();
const answered = await spawned({ ...digested, read: reader("records") }, digestTurn("s-hit", []));
if (answered.outcome.kind !== "recalled") problems.push(`a bundle with records gave ${answered.outcome.kind} on an opening turn`);
if (injectionFrom(answered.outcome)?.prependContext?.includes(DIGEST_HEADING)) {
  problems.push("a digest was injected beside a bundle that answered");
}
if (answered.asked.some((line) => line.startsWith("records"))) problems.push(`a bundle that answered still spent a window read: ${answered.asked.join(" | ")}`);

// **A page of the actor does not.** This is the regression the allowance exists to end, and it is the
// one with no symptom: the rule read "a bundle takes the turn", and it was written when a bundle
// meant an answer. The moment the actor half began to match, every turn came back with a full bundle
// of the asking agent's own week, so the digest -- shipped the day before -- had no turn left to fire
// on. Measured on the live deployment: with `actors` set, no digest on any of four probe turns; with
// it unset, the greeting produced one. The mechanism was intact the whole time.
SEEN_SESSIONS.clear();
const keyless = await spawned(
  { ...digested, read: reader("background"), actors: { main: "main_bot" } },
  digestTurn("s-keyless", []),
);
if (keyless.asked.some((line) => line.includes("--actor"))) {
  problems.push(`a turn with no answer under it still read the actor's page: ${keyless.asked.join(" | ")}`);
}
if (keyless.outcome.kind !== "empty") {
  problems.push(`a mapped actor answered a turn whose keys matched nothing: ${keyless.outcome.kind}`);
}
if (!injectionFrom(keyless.outcome)?.prependContext?.includes(DIGEST_HEADING)) {
  problems.push(`a mapped actor took the opening turn from the digest: ${JSON.stringify(keyless.outcome)}`);
}

// **A ranked search does not.** The fallback's own heading concedes its records may not be about the
// message, so a turn holding only that has been handed a rank rather than an answer. Measured rather
// than reasoned about: this host prefixes a timestamp to the prompt, so the needle carries the date
// and the fallback answers the clock on every turn -- under a rule where any recall took the space,
// no digest would ever have been injected on the deployment this was built for.
SEEN_SESSIONS.clear();
const ranked = await spawned(
  { ...digested, read: reader("fallback") },
  turnOf({ threadEntity: "chat_thread" }, { prompt: "WUPGHGJ7ELJM626", messages: [] }, { agentId: "main", sessionKey: "s-ranked" }),
);
if (ranked.outcome.kind !== "recalled") problems.push(`the fallback did not recall on an opening turn: ${ranked.outcome.kind}`);
const both = injectionFrom(ranked.outcome)?.prependContext ?? "";
if (!both.startsWith(SEARCH_HEADING)) problems.push("the stronger claim was not rendered first");
if (!both.includes(DIGEST_HEADING)) problems.push("a ranked hit took the turn from the digest");

// **A digest that fails costs the turn nothing.** The bundle succeeded and matched nothing, which is
// an answer; a window read that could not be made must not turn that into an outage.
SEEN_SESSIONS.clear();
const brokenDigest = recorder();
const halfBroken = await spawned({ ...digested, read: reader("digest-broken") }, digestTurn("s-halfbroken", []));
report(halfBroken.outcome, brokenDigest);
if (halfBroken.outcome.kind !== "empty") problems.push(`a failed digest turned an empty store into ${halfBroken.outcome.kind}`);
if (injectionFrom(halfBroken.outcome) !== undefined) problems.push("a failed digest injected something");
if (said(brokenDigest, "warn")) problems.push(`a failed digest warned: ${said(brokenDigest, "warn")}`);
if (!/no session-opening digest/.test(said(brokenDigest, "info"))) problems.push("a failed digest was not reported at all");
if (!/matched nothing/.test(said(brokenDigest, "info"))) problems.push("a failed digest hid the empty match beside it");

// **And a recall that fails does not take the digest with it.** The bundle was refused; the window is
// a different question over the same socket, and where it answers the turn still gets one.
SEEN_SESSIONS.clear();
const digestOnlyLog = recorder();
const digestOnly = await spawned({ ...digested, read: reader("digest-only") }, digestTurn("s-refused", []));
report(digestOnly.outcome, digestOnlyLog);
if (digestOnly.outcome.kind !== "unavailable") problems.push(`a refused bundle gave ${digestOnly.outcome.kind}`);
if (!/recall unavailable/.test(said(digestOnlyLog, "warn"))) problems.push("a refused bundle stopped being warned about once a digest arrived");
if (!injectionFrom(digestOnly.outcome)?.prependContext?.includes(DIGEST_HEADING)) {
  problems.push("a refused bundle took the digest down with it");
}

// **Provenance and shape.** A third heading, in the same register as the second and weaker again: not
// a claim about this message at all. Grouped by date, and capped lists say what they left out.
SEEN_SESSIONS.clear();
const block = injectionFrom((await spawned({ ...digested, read: reader("digest") }, digestTurn("s-shape", []))).outcome).prependContext;
if (!block.startsWith(DIGEST_HEADING)) problems.push(`the digest did not say what it is: ${block.slice(0, 80)}`);
if (block.includes(HEADING) || block.includes(SEARCH_HEADING)) problems.push("the digest was injected under a heading that claims more than it can");
for (const expected of ["\n2026-08-28\n", "\n2026-08-26\n", "agent=deploy_bot", "entities=ticket:PROJ-42", "last 14 day(s)"]) {
  if (!block.includes(expected)) problems.push(`the digest dropped ${JSON.stringify(expected)}: ${block}`);
}
// Structure and nothing else: the honest limit of every read here, and the heading says so -- as a
// limit on the read, because the bodies it does not carry do exist.
if (!/Record structure only/.test(block)) problems.push("the digest did not say it carries structure only");
if (!/records have bodies, and by design no read here returns one/.test(block)) {
  problems.push(`the digest misdescribed the limit as an empty store: ${block.slice(0, 200)}`);
}
// A digest cut by its row cap, and one cut by its character ceiling. The two are separate sentences
// because they are separate cuts with separate fixes: raising `digestMaxChars` does nothing about a
// window the read never returned, and a reader who cannot tell them apart raises the wrong one.
SEEN_SESSIONS.clear();
const cappedDigest = injectionFrom(
  (await spawned({ ...digested, digestMaxRecords: 1, read: reader("digest") }, digestTurn("s-capped", []))).outcome,
).prependContext;
if (!cappedDigest.includes(DIGEST_TRUNCATED_NOTE)) {
  problems.push(`a digest cut by its row cap did not say the window held more: ${cappedDigest}`);
}
SEEN_SESSIONS.clear();
const squeezedDigest = injectionFrom(
  (await spawned({ ...digested, digestMaxChars: 110, read: reader("digest") }, digestTurn("s-squeezed", []))).outcome,
).prependContext;
if (!/1 further record/.test(squeezedDigest)) {
  problems.push(`a digest cut by its character ceiling did not say what it left out: ${squeezedDigest}`);
}

// **The window read is bounded as a window read.** Both bounds or neither -- the reader refuses one
// alone on the grounds that it asks a different question -- and none of the bundle's own flags, which
// `records` does not take and every fake reader here accepts happily.
SEEN_SESSIONS.clear();
const window = (await spawned({ ...digested, read: reader("digest") }, digestTurn("s-bounds", []))).asked
  .find((line) => line.startsWith("records"));
if (!window) problems.push("no window read was made on an opening turn");
else {
  for (const flag of ["--from-ms", "--to-ms", "--limit", "--timeout-ms"]) {
    if (!window.includes(flag)) problems.push(`the window read was not given ${flag}: ${window}`);
  }
  if (window.includes("--deadline-ms")) problems.push(`the window read passed a bundle-only flag: ${window}`);
  if (window.includes("--actor") || window.includes("--entity")) {
    problems.push(`the window read was narrowed to this turn, which is not what it asks: ${window}`);
  }
  const [, from] = window.match(/--from-ms (\d+)/) ?? [];
  const [, to] = window.match(/--to-ms (\d+)/) ?? [];
  if (!from || !to || Number(to) - Number(from) !== 14 * 86400000) {
    problems.push(`the window was not the configured 14 days: ${window}`);
  }
}

// --- a page at the read's limit says it is a page -------------------------------------------------
// The `bundle` read reports its own cap: the service reads one row past the limit and says
// `degraded` with the overflow in `omitted`. `search` and `records` do neither -- they hand back a
// page, no total and no flag -- so a page exactly as long as the limit reads as the whole answer.
//
// Measured on the live deployment before this existed: of 116 recall lines, 98 reported exactly
// `maxRecords` records and all 33 digests reported exactly `digestMaxRecords`; three needles that
// returned 8 rows at `--limit 8` returned 14, 22 and 21 at `--limit 100`, and the digest's own
// window held 23 rows for the 12 it asked for. Every one of those pages was cut and none said so.
const cutSettings = {
  read: reader("over"), maxRecords: 3, maxChars: 8192,
  digestDays: 14, digestMaxRecords: 4, digestMaxChars: 8192,
};
const cutArgs = `${binDir}/../cut-args`;
process.env.READER_ARGS_FILE = cutArgs;
const cut = await recall(cutSettings, { agentId: "main", text: "what did the loader decide", opening: true });
delete process.env.READER_ARGS_FILE;
const cutReads = (await import("node:fs")).readFileSync(cutArgs, "utf8").trim().split("\n");
const cutBlock = injectionFrom(cut)?.prependContext ?? "";

if (cut.kind !== "recalled" || cut.via !== SEARCH_SHAPE) {
  problems.push(`the full-page reader did not answer via search: ${JSON.stringify(cut)}`);
}
if (!cutBlock.includes(TRUNCATED_NOTE)) problems.push(`a page at the read's limit did not say it was a page: ${cutBlock}`);
if (!cutBlock.includes(DIGEST_TRUNCATED_NOTE)) problems.push(`a digest at its limit did not say the window held more: ${cutBlock}`);

// --- the over-read row is evidence, never content -------------------------------------------------
// The extra row buys a sentence, not a bigger page. Rendering it would spend the tokens the whole
// choice was made to avoid, and would put the page one row over the ceiling an operator configured.
if (cut.count !== 3) problems.push(`the over-read row was counted into the answer: ${cut.count}`);
if ((cutBlock.match(/^- at=/gm) ?? []).length !== 3) {
  problems.push(`the over-read row was rendered: ${cutBlock}`);
}
if (cut.digestCount !== 4) problems.push(`the digest's over-read row was counted: ${cut.digestCount}`);
{
  const searchRead = cutReads.find((line) => line.startsWith("search "));
  const windowRead = cutReads.find((line) => line.startsWith("records "));
  if (!searchRead?.includes(`--limit ${3 + OVER_READ}`)) {
    problems.push(`the search read asked for only the page it would show: ${searchRead}`);
  }
  if (!windowRead?.includes(`--limit ${4 + OVER_READ}`)) {
    problems.push(`the window read asked for only the page it would show: ${windowRead}`);
  }
}

// --- a page under the limit claims nothing --------------------------------------------------------
// The sentence has to be a fact about the read rather than a guess from the page's size, or it fires
// on every turn and stops being read -- the failure `background-degrades-the-answer` guards against
// one source over.
const uncut = await recall({ ...digested, read: reader("fallback"), maxRecords: 8 }, digestTurn("s-uncut", []));
const uncutBlock = injectionFrom(uncut)?.prependContext ?? "";
if (uncutBlock.includes(TRUNCATED_NOTE)) problems.push(`a short page claimed it was cut: ${uncutBlock}`);
if (uncutBlock.includes(DIGEST_TRUNCATED_NOTE)) problems.push(`a short digest claimed the window held more: ${uncutBlock}`);

// --- recording is a hook, and what it may say ------------------------------------------------------
// `agent_end` fires after a turn is settled and returns nothing: there is no field on its result that
// could change what the turn said. What it *knows* is that a turn ran, which agent ran it, which
// conversation it ran in and whether it finished -- so that is what it records, and nothing else.
const emitter = (name) => [`${binDir}/emitter-${name}`, "--socket", "/dev/null", "--agent", "some_bot"];
const recordWired = {
  recordAction: "answer",
  recordOutcomes: { success: "success", failure: "partial" },
  recordAttrs: { channel: "channel", recalled: "recalled" },
  threadEntity: "chat_thread",
  record: { main: emitter("ok") },
};
const wrote = async (settings, event, ctx, facts) => {
  const file = `${binDir}/../emit-args-${Math.random().toString(36).slice(2)}`;
  process.env.EMITTER_ARGS_FILE = file;
  const log = recorder();
  const outcome = await recordTurn(settings, event, ctx, facts ?? {});
  reportRecord(outcome, log);
  delete process.env.EMITTER_ARGS_FILE;
  const fs = await import("node:fs");
  const lines = fs.existsSync(file) ? fs.readFileSync(file, "utf8").trim() : "";
  return { outcome, log, argv: lines ? lines.split("\n") : [] };
};
const turnCtx = {
  agentId: "main", runId: "run-1", channelId: "c0example:thread:1700000000.000100",
  sessionKey: "s-record",
};
// A distinctive token in everything the turn said. It must appear nowhere on the record's line: the
// turn's text is the only thing in the event that could name a person, and it is never read into a
// record. That is what makes `subjects:` empty by construction rather than by care.
const SECRET = "zqx-turn-text-marker";
const turnEvent = {
  runId: "run-1", success: true, durationMs: 1234,
  messages: [{ role: "user", content: SECRET }, { role: "assistant", content: `about ${SECRET}` }],
};

const recorded = await wrote(recordWired, turnEvent, turnCtx, { channel: "c0example", recalled: true });
if (recorded.outcome.kind !== "wrote") problems.push(`a finished turn was not recorded: ${JSON.stringify(recorded.outcome)}`);
if (recorded.argv.length !== 1) problems.push(`a turn produced ${recorded.argv.length} records, not one`);
{
  const line = recorded.argv[0] ?? "";
  for (const expected of ["--action answer", "--outcome success", "--entity=chat_thread:c0example/1700000000.000100",
                          "--attr=channel=c0example", "--attr-bool=recalled=true"]) {
    if (!line.includes(expected)) problems.push(`the record did not carry ${expected}: ${line}`);
  }
  if (!line.includes(RECORD_SUMMARY)) problems.push(`the record did not carry the fixed summary: ${line}`);
  if (line.includes(SECRET)) problems.push("the turn's own text reached the record");
  for (const forbidden of ["--subject", "--data-class", "--infer-entities", "--infer-from", "--backfilled"]) {
    if (line.includes(forbidden)) problems.push(`the record's line carried ${forbidden}: ${line}`);
  }
}

// --- the hook's record is the complement of the agent's, not a duplicate -------------------------
// A turn that recorded already has a row naming the action and saying why it mattered, so a floor
// beside it would be a second row about one event carrying less. The question is asked of the store
// -- did this agent's writer file anything while the turn was running -- over the read socket recall
// already uses, and the window is the turn itself.
//
// **The transcript was tried first and cannot answer it.** Scanning the turn's messages for the
// recorder's name is free and works on the embedded backend. On a CLI backend it cannot: measured,
// `agent_end` there is handed the session history plus this turn's prompt and last assistant
// message, and the tool calls run in a process the gateway never sees. A suppression that silently
// cannot fire is worse than none.
// `reader-digest` answers the window read with rows; `reader-empty` answers it with none.
const probing = { ...recordWired, read: reader("digest"), actors: { main: "main_bot" } };
const suppressed = await wrote(probing, turnEvent, turnCtx, {});
if (suppressed.outcome.kind !== "recorded-already") {
  problems.push(`the hook wrote a second row for a turn that recorded itself: ${JSON.stringify(suppressed.outcome)}`);
}
if (suppressed.argv.length !== 0) problems.push("the hook spawned a recorder for a turn that had already recorded");
// The same probe over a store that filed nothing in that window: the row is written.
const quiet = await wrote({ ...probing, read: reader("empty") }, turnEvent, turnCtx, {});
if (quiet.outcome.kind !== "wrote") problems.push(`a turn nobody recorded was not given a floor row: ${quiet.outcome.kind}`);

// It asks about the turn and nothing wider. A window reaching back past the turn would catch the
// previous turn's own floor record and stand down for ever after the first one.
{
  const file = `${binDir}/../probe-args-${Math.random().toString(36).slice(2)}`;
  process.env.READER_ARGS_FILE = file;
  await recordedDuring({ read: reader("empty") }, "some_bot", { durationMs: 4321 }, 2000);
  delete process.env.READER_ARGS_FILE;
  const asked = (await import("node:fs")).readFileSync(file, "utf8").trim();
  if (!asked.startsWith("records ")) problems.push(`the probe did not ask the window read: ${asked}`);
  if (!asked.includes("--agent some_bot")) problems.push(`the probe did not name the writer: ${asked}`);
  if (!asked.includes("--limit 1")) problems.push(`the probe read more than the one row it needs: ${asked}`);
  const [, from] = asked.match(/--from-ms (\d+)/) ?? [];
  const [, to] = asked.match(/--to-ms (\d+)/) ?? [];
  if (!from || !to || Number(to) - Number(from) !== 4321) {
    problems.push(`the probe's window was not the turn: ${asked}`);
  }
  if (asked.includes("--entity") || asked.includes("--actor")) {
    problems.push(`the probe was narrowed to something other than the writer: ${asked}`);
  }
}
// Every way of not knowing writes the row, and says which way it was.
for (const [label, settings, event] of [
  ["no writer name for this agent", { ...recordWired, read: reader("digest") }, turnEvent],
  ["no reader to ask", probing, turnEvent],
  ["no duration from the host", probing, { ...turnEvent, durationMs: undefined }],
  ["a probe that was refused", { ...probing, read: reader("refused") }, turnEvent],
]) {
  const blind = await wrote(label === "no reader to ask" ? { ...settings, read: undefined } : settings,
    event, turnCtx, {});
  if (blind.kind === "recorded-already") problems.push(`${label} was read as the turn having recorded itself`);
  if (blind.outcome.kind !== "wrote") problems.push(`${label} did not write the floor row: ${blind.outcome.kind}`);
  if (!/without checking/.test(said(blind.log, "info"))) {
    problems.push(`${label} did not say the store went unasked: ${said(blind.log, "info")}`);
  }
}

// --- a hook must not degrade a turn ----------------------------------------------------------------
// Recall fails open because a memory service that is down must not be a turn that will not start.
// Recording fails open for the mirror reason: a store that is unreachable must not be a turn that
// will not finish. Every one of these resolves, none of them throws, and each says which happened.
for (const [label, settings, expected] of [
  ["a recorder that is not there", { ...recordWired, record: { main: [`${binDir}/emitter-absent`] } }, "failed"],
  ["a refused record", { ...recordWired, record: { main: emitter("refused") } }, "failed"],
  ["a recorder that never answered", { ...recordWired, record: { main: emitter("slow") }, recordTimeoutMs: 200 }, "failed"],
]) {
  const attempt = await wrote(settings, turnEvent, turnCtx, {});
  if (attempt.outcome.kind !== expected) problems.push(`${label} gave ${attempt.outcome.kind}, not ${expected}`);
  if (!attempt.outcome.why) problems.push(`${label} gave no reason`);
  if (!/could not be recorded/.test(said(attempt.log, "warn"))) problems.push(`${label} was not reported`);
}
// And the spool, which is the one exit code that looks like a failure and is not.
const spooled = await wrote({ ...recordWired, record: { main: emitter("spooled") } }, turnEvent, turnCtx, {});
if (spooled.outcome.kind !== "wrote") problems.push(`a spooled record was read as a failure: ${JSON.stringify(spooled.outcome)}`);
if (said(spooled.log, "warn")) problems.push(`a spooled record warned: ${said(spooled.log, "warn")}`);

// --- nothing may reach the line that this file did not put there ------------------------------------
// An allowlist and not a deny list: the emitter has no flag for a subject or a data class today, and
// refusing every flag this file has not reasoned about is what keeps that true of a flag it grows
// tomorrow. A refused argv records nothing and names what it refused.
for (const smuggled of ["--subjects", "--data-class", "--infer-entities", "--summary", "-x"]) {
  const why = unwritable([`${binDir}/emitter-ok`, smuggled, "whatever"]);
  if (!why || !why.includes(smuggled)) problems.push(`a recorder argv carrying ${smuggled} was accepted: ${why}`);
  const attempt = await wrote({ ...recordWired, record: { main: [`${binDir}/emitter-ok`, smuggled, "x"] } }, turnEvent, turnCtx, {});
  if (attempt.outcome.kind !== "refused") problems.push(`${smuggled} in the argv still recorded: ${attempt.outcome.kind}`);
  if (attempt.argv.length !== 0) problems.push(`${smuggled} in the argv reached a process`);
}
if (unwritable([`${binDir}/emitter-ok`, "--socket", "/tmp/x", "--agent", "a"])) {
  problems.push("the flags that say who is writing were refused");
}

// --- a turn nobody named an outcome for is declined, not filed as a success -------------------------
// A store refuses a record whose action does not declare the outcome it carries, and this file has
// never seen that declaration. Filing a failed turn as a success because the schema had no word for
// failure is the default the emitter itself refuses to have.
const failedTurn = await wrote(recordWired, { ...turnEvent, success: false }, turnCtx, {});
if (!(failedTurn.argv[0] ?? "").includes("--outcome partial")) {
  problems.push(`a failed turn was not filed under the outcome the config named: ${failedTurn.argv[0]}`);
}
const undeclared = await wrote({ ...recordWired, recordOutcomes: { success: "success", failure: "" } },
  { ...turnEvent, success: false }, turnCtx, {});
if (undeclared.outcome.kind !== "undeclared") problems.push(`a turn with no declared outcome gave ${undeclared.outcome.kind}`);
if (undeclared.argv.length !== 0) problems.push("a turn with no declared outcome was recorded anyway");

// --- and the three ways recording is off ------------------------------------------------------------
for (const [label, settings, expected] of [
  ["no action configured", { ...recordWired, recordAction: undefined }, "off"],
  ["no recorder for this agent", { ...recordWired, record: { other: emitter("ok") } }, "unmapped"],
  ["no recorders at all", { ...recordWired, record: undefined }, "off"],
]) {
  const attempt = await wrote(settings, turnEvent, turnCtx, {});
  if (attempt.outcome.kind !== expected) problems.push(`${label} gave ${attempt.outcome.kind}, not ${expected}`);
  if (attempt.argv.length !== 0) problems.push(`${label} spawned a recorder anyway`);
}
// A heartbeat is the host talking to itself on a timer. A floor record per tick is a clock in the
// store rather than work, and it would crowd out the rows an answer is composed from.
const tick = await wrote(recordWired, turnEvent, { ...turnCtx, trigger: "heartbeat" }, {});
if (tick.outcome.kind !== "skipped") problems.push(`a heartbeat turn gave ${tick.outcome.kind}`);
if (tick.argv.length !== 0) problems.push("a heartbeat turn was recorded");

for (const problem of problems) console.log(`::error::openclaw recall: ${problem}`);
process.exit(problems.length ? 1 : 0);
JS
  plugin="$PWD/harnesses/openclaw/memory-plugin/index.mjs"
  node "$work/recall-assertions.mjs" "$plugin" "$memwork/bin" || status=1
  [ "$status" -eq 0 ] && note "injects structure; fails open on no reader, no binary, a refusal, \
garbage and no answer; and an empty match reads differently"

  echo "→ the fail-open assertions can fail: breaking each one is caught"
  # Two agents this week shipped a guard that silently allowed everything. The way that ships is
  # assertions that pass whatever the code does, so each claim is checked by breaking it on a copy
  # and requiring the run to go red.
  mutant_dir="$work/mutants"
  mkdir -p "$mutant_dir"
  survived=0
  mutate() {
    local name="$1" expression="$2" out="$mutant_dir/$1.mjs"
    sed "$expression" "$plugin" > "$out"
    cmp -s "$out" "$plugin" && {
      fail "mutant $name changed nothing, so it proves nothing"
      return
    }
    if node "$work/recall-assertions.mjs" "$out" "$memwork/bin" >/dev/null 2>&1; then
      fail "mutant $name survived: the assertions do not exercise that path"
      survived=1
    else
      note "mutant $name was caught"
    fi
  }
  # A failure that injects whatever it has: the fail-open path stops being distinguishable from a hit.
  mutate injects-on-failure 's/if (outcome?.kind === "recalled") blocks.push/if (outcome?.kind !== "impossible") blocks.push/'
  # A quiet store reported as a broken one: the distinction the log exists to keep.
  mutate empty-as-failure 's/if (!fallback) return { kind: "empty", asked: named, actor };/if (!fallback) return { kind: "unavailable", why: "no rows" };/'
  # The fallback presenting a ranked keyword hit as a composed bundle: the provenance the second
  # heading exists to keep. This is the mutant that matters most about the fallback -- everything
  # else it could get wrong is visible, and this one reads as a better answer than it is.
  mutate search-as-bundle 's/limits, SEARCH_HEADING, { asked: named, via: SEARCH_SHAPE, actor });/limits, HEADING, { asked: named, via: READ_SHAPE, actor });/'
  # A needle that keeps the question mark: the syntax error that made the first version useless.
  mutate needle-unquoted 's/terms.push(`"${word}"`);/terms.push(word);/'
  # The host's envelope left on the front of the message. This is the defect the numbers above came
  # from: it has no symptom at all, because the fallback answers every turn and the log calls it a
  # recall -- it just answers about the date rather than about the question.
  mutate envelope-not-stripped 's|const message = withoutEnvelope(prompt);|const message = prompt;|'
  # The calendar back in the needle, for a date nobody prepended. The envelope strip does not cover
  # this and cannot: the words are the person's own.
  mutate needle-keeps-the-calendar 's|if (calendarToken(word)) continue;|if (false) continue;|'
  # The same rule with only its year half broken, because a bare `2026` is the single term that did
  # the most damage -- on the live store it matched 36 of 73 records by itself.
  mutate needle-keeps-the-year 's|YEAR_SHAPED.test(folded)|false|'
  # A stripper that takes the front off whatever arrives. The failure this trades for the other one:
  # a needle that lost the identifier is as useless as a needle that searched the clock, and quieter.
  mutate envelope-eats-the-message 's|if (!tail \|\| !envelopeLine(head)) break;|if (false) break;|'
  # The fallback bounded as though it were a bundle: a usage error the real reader refuses and every
  # fake accepts.
  mutate fallback-bundle-bounds 's/searchBounds(argvSearch, left/bounds(argvSearch, left/'
  # A fallback that fires whatever the config says.
  mutate fallback-ignores-config 's/if (settings?.searchFallback === false) return undefined;/if (false) return undefined;/'
  # A lookup that ran out of time inventing an answer instead of admitting it.
  mutate timeout-invents 's|child.kill("SIGKILL");|answer({ kind: "recalled", context: "invented", count: 1 }); return;|'
  # A turn that stops naming its thread. This is the failure the plugin was built to end, and it has
  # no symptom of its own: recall just goes quiet, exactly as it does on a genuinely empty store.
  mutate thread-never-found 's|const at = channelId.indexOf(THREAD_MARKER);|const at = -1;|'
  # The thread named under a separator no record joins on, which is the same silence one step later.
  mutate thread-mis-spelled 's|return `${conversation}/${thread}`;|return `${conversation}:${thread}`;|'
  # The message never read for entities, so the other half of the lookup goes missing.
  mutate message-never-read 's|if (!text \|\| typeof specDir !== "string"|if (true \|\| typeof specDir !== "string"|'

  # --- an agent id is not a writer name ---
  # The defect that shipped, restored exactly: an agent the map does not name has its *id* sent as the
  # actor. On the live store that asked about `main`, `pr` and `deploy`, which nothing was ever written
  # by, so the actor half of every bundle matched nothing and the answer was an empty page --
  # indistinguishable from a quiet store, which is why it survived shipping. This is the mutant this
  # section exists for.
  mutate actor-unmapped-id-passed \
    's|if (typeof writer !== "string") return { kind: "unmapped", agentId: id };|if (typeof writer !== "string") return { kind: "named", writer: id };|'
  # The same failure by the tidier route: a suffix rule instead of a map. It would have worked on this
  # one deployment, which is the whole objection -- a convention that returns a string cannot be told
  # apart from a fact that returns a string, and the next host to name a writer differently gets the
  # silent zero back with a rule behind it.
  mutate actor-suffix-invented \
    's|const writer = actors \&\& typeof actors === "object" ? actors\[id\] : undefined;|const writer = (actors \&\& typeof actors === "object" ? actors[id] : undefined) ?? (id + "_bot");|'
  # A writer name that would be parsed as a flag, reaching the argument list.
  mutate actor-flag-shaped-writer 's|if (!trimmed \|\| trimmed.startsWith("-")) return { kind: "unmapped", agentId: id };|if (!trimmed) return { kind: "unmapped", agentId: id };|'
  # And the silence itself: the omission is correct and invisible unless the log says it happened.
  # Without this line an operator sees `via search` on every turn and no reason anywhere.
  mutate actor-unmapped-unsaid 's|if (plan?.kind !== "unmapped") return;|if (true) return;|'

  # --- the actor is background, and is bounded like one ---
  # The two regressions a correct fix caused, each restored exactly. Both shipped green: the actor
  # half matching is what the map was for, and neither of these has a symptom that looks like a bug.

  # **The actor back on the read that answers the turn.** One read with one `--limit` cannot bound two
  # sources separately -- the service fills entities first and gives the actor the rest -- so this is
  # the actor taking whatever the keys left, which on a turn naming no key is the whole page. Measured
  # on the live store: a greeting, a prose question and a generic question returned the same eight
  # rows, byte for byte, under the heading that says a bundle composed them around the request.
  mutate actor-fills-the-page \
    's|    ...inferenceFor(base, settings?.specDir, turn?.text),|    ...inferenceFor(base, settings?.specDir, turn?.text), ...actorFor(base, turn?.agentId, settings?.actors),|'
  # The same failure by the other route: the allowance stops being an allowance and becomes "whatever
  # is left", which is the service's own rule restated in this file. It reads as a bound and is not.
  mutate actor-allowance-unbounded \
    's|return Math.max(0, Math.min(most, limits.maxRecords - shown));|return Math.max(0, limits.maxRecords - shown);|'
  # **The actor's overflow setting `degraded` again.** `--limit N` reads N+1 so that "there is more"
  # is a fact rather than a guess, so an actor with more history than its share is *always* degraded.
  # Carried onto the answer, that sentence -- the one telling a model what it may act on -- fires on
  # every turn for ever, and a warning that is always on is a warning nobody reads.
  mutate background-degrades-the-answer \
    's|background: { writer: page.writer, shown: added.length, more: page.more === true },|background: { writer: page.writer, shown: added.length, more: page.more === true }, degraded: page.more === true,|'
  # And the other way to be dishonest about a cut source: drop it silently. `omitted` exists to say
  # what was left out, so a background page that is bounded without saying so is a page of one agent's
  # week presented as part of the answer.
  mutate background-unlabelled 's|if (background \&\& carried > 0) {|if (false) {|'
  # The bound applied to the read but not to what is kept, which is the same hole one step later: an
  # operator's own `--limit` in the argv is left alone by `bounds`, so the trim is what actually holds.
  mutate background-trim-dropped 's|const records = answer.records.slice(0, plan.allowance);|const records = answer.records;|'

  # --- the session-opening digest ---
  # The two that matter most, first. This hook fires every turn, so a digest that lost its fence is a
  # block of tokens in front of every message a person sends -- and it has no symptom: it looks
  # exactly like the feature working, only more often.
  mutate digest-on-every-turn 's|if (turn?.opening !== true) return undefined;|if (false) return undefined;|'
  # And the other half of the fence: a digest nobody configured is the same cost arriving unasked.
  mutate digest-ignores-config 's|if (days <= 0) return undefined;|if (false) return undefined;|'
  # A digest failure taking recall down with it. The bundle answered and matched nothing, which is an
  # answer about the store; reporting it as an outage because a read nobody asked for was refused
  # would call a working store broken, and put a warning in a log that has to stay readable.
  mutate digest-failure-sinks-recall \
    's|if (answer.kind === "failed") return { ...outcome, digestFailed: answer.why };|if (answer.kind === "failed") return { kind: "unavailable", why: answer.why };|'
  # The same isolation, run the other way: a bundle that could not be asked is not a socket that went
  # away, and the window read over the same socket may well answer.
  mutate recall-failure-sinks-digest \
    's|return withDigest(outcome, settings, argv, turn, deadline);|return outcome.kind === "unavailable" ? outcome : withDigest(outcome, settings, argv, turn, deadline);|'
  # A digest injected beside the composed answer to the question that was asked. Half the budget rule,
  # and breaking it spends the turn's tokens twice.
  mutate digest-outranks-a-bundle \
    's|if (outcome.kind === "recalled" \&\& outcome.via === READ_SHAPE) return outcome;|if (false) return outcome;|'
  # The other half: a ranked keyword hit taking the turn from the digest. This is the one that would
  # have made the feature inert on a live host, where the fallback answers the date in the prompt's
  # own timestamp every single turn.
  mutate digest-yields-to-a-ranked-hit 's|outcome.kind === "recalled" \&\& outcome.via === READ_SHAPE|outcome.kind === "recalled"|'
  # Background presented as an answer: the same provenance failure as search-as-bundle, one step
  # further out, because a digest is not about this message at all.
  mutate digest-as-recall 's|return \[DIGEST_HEADING, ...lines|return [HEADING, ...lines|'
  # Half a window. The reader refuses one bound alone -- it asks a different question rather than a
  # narrower one -- and every fake reader in this file accepts it, which is exactly how the search
  # fallback shipped broken once already.
  mutate digest-half-window 's|, "--to-ms", String(to)||'
  # And the window read bounded as though it were a bundle, which is the same usage error by the
  # other route.
  mutate digest-bundle-bounds 's|digestBounds(argvDigest, left|bounds(argvDigest, left|'
  # The heading telling the model the store holds nothing more, restored exactly. Every read here
  # returns structure by design and record bodies exist, so this one is false rather than merely
  # blunt: it talks an agent out of naming the record whose body it could have asked for.
  mutate digest-denies-the-bodies \
    's|was about: records have " +|was about, and this " +|; s|"bodies, and by design no read here returns one.";|"store holds no prose that could.";|'

  # --- a page at the read's limit says it is a page ---
  # The two reads with no cap of their own. `bundle` reports its overflow as `degraded`; `search` and
  # `records` report nothing at all, so a page the size of the limit reads as the whole answer. On
  # the live deployment 98 of 116 recall lines and every one of 33 digests were exactly at their cap.
  mutate page-not-over-read 's|return String(maxRecords + OVER_READ);|return String(maxRecords);|'
  # And the digest's own answer left uncut, which is the same claim reached from the other end: the
  # window read was the one at its cap on every single turn it fired.
  mutate digest-page-uncut \
    's|const window = page(answer, plan.limits.maxRecords);|const window = { ...answer, truncated: false };|'
  # The over-read row rendered instead of counted: the sentence bought with tokens the choice was
  # made to avoid, and a page one row past the ceiling an operator set.
  mutate over-read-row-shown 's|records: records.slice(0, most), truncated: records.length > most|records, truncated: records.length > most|'
  # The fact known and not said, which is the same failure as `background-unlabelled` one source over.
  mutate search-cut-unlabelled 's|if (answer?.truncated === true) notes.push(TRUNCATED_NOTE);|if (false) notes.push(TRUNCATED_NOTE);|'
  mutate digest-cut-unlabelled 's|if (answer?.truncated === true) notes.push(DIGEST_TRUNCATED_NOTE);|if (false) notes.push(DIGEST_TRUNCATED_NOTE);|'
  # A page called cut because it is full. The sentence has to be a fact about the read rather than a
  # guess from the page's size, or it fires on every turn and stops being read.
  mutate cut-guessed-from-the-page 's|truncated: records.length > most|truncated: records.length >= most|'

  # --- recording is a hook, and it may not read the turn ---
  # **The subject guarantee, seen from the one place it could break.** The turn's text is the only
  # thing in the event that could name a person; nothing may carry it into a record. A summary built
  # from the message would be plaintext in a body no erasure reaches.
  mutate record-reads-the-message \
    's|    RECORD_SUMMARY,|    RECORD_SUMMARY + JSON.stringify(event?.messages ?? ""),|; s|function recordArgs(settings, argv, action, outcome, facts, thread)|function recordArgs(settings, argv, action, outcome, facts, thread, event)|; s|recordArgs(settings, argv, action, outcome, facts, thread ? `${kind}:${thread}` : undefined)|recordArgs(settings, argv, action, outcome, facts, thread ? `${kind}:${thread}` : undefined, event)|'
  # The allowlist turned into a pass. It is what keeps a flag the emitter has not grown yet off this
  # line, so a deny list -- or none -- is the shape that ships the hole.
  mutate record-any-flag-allowed 's|if (!RECORD_ALLOWED_FLAGS.has(flag)) {|if (false) {|'
  # Two rows for one event: the hook writing a floor beside the agent's own richer record.
  mutate record-ignores-suppression 's|if (already.recorded) return { kind: "recorded-already"|if (false) return { kind: "recorded-already"|'
  # A probe that cannot answer read as an answer. Every way of not knowing has to write the row: a
  # miss costs one extra floor record, and this costs the record, which is the state being replaced.
  mutate record-unknown-is-suppression \
    's|if (answer.kind === "failed") return { recorded: false, why: answer.why };|if (answer.kind === "failed") return { recorded: true };|'
  # The window widened past the turn. It would then catch the *previous* turn's own floor record, and
  # the hook would stand down for ever after the first one -- coverage collapsing to a single row
  # with nothing in the log looking wrong.
  mutate record-window-outlives-the-turn \
    's|String(to - Math.max(0, Math.floor(event.durationMs)))|String(to - 86400000)|'
  # And the probe not saying it went unasked, which is the only thing an operator can act on when a
  # second row shows up beside an agent's own.
  mutate record-blind-write-unsaid 's|const blind = outcome.unasked ?|const blind = false ?|'
  # The spool read as an outage. Exit 7 is the sidecar holding a record and still delivering it, so
  # this reports a failure every time one is ridden out -- and the record lands anyway.
  mutate record-spool-is-a-failure 's|code === 0 \|\| code === SPOOLED_EXIT|code === 0|'
  # A failed turn filed as a success because the outcome map had no word for it. The emitter refuses
  # to default an outcome for exactly this reason: no later read could tell.
  mutate record-failure-as-success 's|const key = success ? "success" : "failure";|const key = "success";|'
  # A heartbeat recorded: a clock in the store rather than work, on every tick, crowding out the rows
  # an answer is composed from.
  mutate record-heartbeat-recorded 's|if (SKIPPED_TRIGGERS.has(ctx?.trigger))|if (false)|'
  # An agent the map does not name recorded anyway. A record carries whatever caller its socket
  # signed as, so a recorder borrowed from another agent files this turn under the wrong writer.
  mutate record-unmapped-agent-recorded \
    's|if (argv === undefined) return { kind: "unmapped", agentId };|if (argv === undefined) argv = Object.values(settings.record)[0];|'
  # A write failure that reaches the turn. `agent_end` is not awaited by the gateway and its handlers
  # are caught, so this cannot in fact break a turn -- but a handler that rejects is a handler whose
  # own report never runs, and the operator loses the one line saying coverage broke.
  mutate record-throws-on-failure \
    's|      failed(`the recorder could not be started: \${error?.message ?? error}`);|      throw error;|'

  [ "$survived" -eq 0 ] || fail "the fail-open path is asserted rather than exercised"
else
  fail "node is not installed, so the recall plugin's outcome path went untested"
fi

if [ "$status" -eq 0 ]; then
  echo "glue: clean — installers parse, the hook refuses, and recall fails open"
fi
exit "$status"
