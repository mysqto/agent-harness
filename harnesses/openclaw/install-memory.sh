#!/usr/bin/env bash
# Wires the read half into an OpenClaw deployment: a plugin that owns `plugins.slots.memory` and
# recalls from this deployment's own memory service before a reply.
#
# Separate from install.sh because it is separate work. That script installs the tool policy, and
# every line of it is generated from spec/tool-policy.json; recall is not a tool rule, and a policy
# generator emitting memory config would put a setting the policy has no opinion on into output the
# policy is supposed to own.
#
# Idempotent, and it never writes the harness's config file — that file is one large JSON5 document
# holding credentials, so this prints the fragment to merge and the validated command that merges it.
# `--apply` runs that command; without it nothing outside the plugin directory is touched.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"

PLUGIN_ID="harness-memory"
READER="${HARNESS_YAAM_READ:-$HOME/.local/bin/yaam-read}"
OPENCLAW="${HARNESS_OPENCLAW:-openclaw}"
CONFIG=""
PLUGIN_DIR="${HARNESS_OPENCLAW_MEMORY_PLUGIN_DIR:-$HOME/.local/share/harness/openclaw-memory-plugin}"
AGENT="main"
SOCKET=""
# The three things that let a bundle name this turn. None has a value this script could guess: the
# entity kind is a deployment's vocabulary rather than this harness's, the spec directory is a path,
# and the writer names are the keyring's. So all three are flags, and the plugin says at load which of
# them is unwired.
THREAD_KIND="chat_thread"
SPEC_DIR=""
# agent id → writer name, comma-separated. Empty is off, and off is the default: a writer name is
# whatever a record socket signed as, so there is nothing here to derive it from and a guess would
# send a `--actor` naming nobody — which returns the same empty page a quiet store returns.
ACTORS=""
# The window a session-opening digest covers, in days. Empty is off, and off is the default: a digest
# is tokens spent on something nobody asked for, and only somebody who can see the store knows whether
# what comes back reads as background or as noise.
DIGEST_DAYS=""
# The write half. All three are empty by default, and empty is off: a store refuses a record whose
# action it never declared, so an action guessed here would be a rejected write on every turn, and a
# recorder guessed here would sign one agent's turns as another. Neither is derivable from anything
# this script can see.
RECORD_ACTION=""
RECORDERS=""
RECORD_OUTCOMES=""
RECORD_ATTRS=""
RECORD_MS=10000
BUDGET_MS=5000
MAX_RECORDS=8
MAX_CHARS=2000
DIGEST_MAX_RECORDS=12
DIGEST_MAX_CHARS=1200
# Written whatever it is, unlike the settings above: the plugin's own default is the same number, and
# an allowance stated in the config is one an operator can read off the file rather than off this
# script. Zero is a real setting here — a deployment that wants no background page at all.
ACTOR_ROWS=2
APPLY=0

usage() {
  cat <<'USAGE'
usage: harnesses/openclaw/install-memory.sh [--config FILE] [--plugin-dir DIR] [--agent NAME]
                                            [--reader PATH] [--socket PATH] [--budget-ms MS]
                                            [--openclaw CMD] [--apply]

  --config FILE     the harness config to merge into. Default follows the documented order:
                    $OPENCLAW_CONFIG_PATH, $OPENCLAW_STATE_DIR/openclaw.json, ~/.openclaw/openclaw.json
  --plugin-dir DIR  where the recall plugin is installed
                    (default ~/.local/share/harness/openclaw-memory-plugin)
  --agent NAME      agent whose read socket recall goes through          (default main)
  --reader PATH     the read tool to spawn                              (default ~/.local/bin/yaam-read)
  --socket PATH     the sidecar's read socket
                    (default ~/.local/state/harness/sockets/<agent>.read.sock)
  --thread-kind K   entity kind conversations are filed under, so a turn in a thread looks that
                    thread up. Empty turns it off.                       (default chat_thread)
  --spec-dir DIR    the deployment's spec directory (entities.yaml, extractors.yaml), so the turn's
                    message is read for entities too. Empty turns it off.        (default: unset)
  --actors MAP      this deployment's map from agent id to the writer name that agent's records were
                    filed under, as `main=main_bot,pr=pr_bot`. An agent id is not a writer name — a
                    record carries whatever caller its socket signed as — so this cannot be derived
                    and is not guessed. An agent left out of the map asks about no actor at all.
                    Empty turns it off.                                          (default: unset)
  --actor-rows N    rows of an answer that may be the actor's own recent activity rather than an
                    answer to the message. The actor is background: it fills what the entities left,
                    up to this many, and carries nothing at all on a turn whose entities matched
                    nothing. 0 turns the background page off.                       (default: 2)
  --digest-days N   days of recent activity a session wakes up holding, injected on the turn that
                    opens a session and only where the turn's own entities found nothing.
                    Empty turns it off.                                          (default: unset)
  --record-action A the action this deployment's attribute schema declares for an agent turn. With
                    --recorders, a turn that ran without recording anything gets a floor record from
                    a post-turn hook. Empty turns recording off.                 (default: unset)
  --recorders MAP   this deployment's map from agent id to that agent's own record tool, as
                    `main=/usr/local/bin/record-main,pr=...`. Per agent because a record carries
                    whatever caller its socket signed as, so another agent's recorder would file the
                    turn under a writer that did not do it. Empty turns recording off.
                                                                                 (default: unset)
  --record-outcomes MAP
                    how this deployment spells the two outcomes a hook can tell apart, as
                    `success=success,failure=failure`, which is also the default. An action with no
                    word for one of the two takes `failure=` — turns of that kind are then not
                    recorded, rather than filed as something they were not.
  --record-attrs MAP
                    which of the hook's two facts reach the record and under which declared keys, as
                    `channel=channel,recalled=recalled`. Only `channel` and `recalled` exist. Empty
                    sends no attributes, which is the default and is accepted everywhere.
  --record-ms MS    how long the record write gets, behind the reply           (default 10000)
  --budget-ms MS    how long one lookup gets, in front of a reply        (default 5000)
  --openclaw CMD    the harness CLI, used to apply                       (default openclaw on PATH)
  --apply           merge the fragment with `openclaw config patch`. Without this, nothing outside
                    the plugin directory is written and the commands are printed instead.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --config)      CONFIG="$2"; shift 2 ;;
    --plugin-dir)  PLUGIN_DIR="$2"; shift 2 ;;
    --agent)       AGENT="$2"; shift 2 ;;
    --reader)      READER="$2"; shift 2 ;;
    --socket)      SOCKET="$2"; shift 2 ;;
    --thread-kind) THREAD_KIND="$2"; shift 2 ;;
    --spec-dir)    SPEC_DIR="$2"; shift 2 ;;
    --actors)      ACTORS="$2"; shift 2 ;;
    --actor-rows)  ACTOR_ROWS="$2"; shift 2 ;;
    --digest-days) DIGEST_DAYS="$2"; shift 2 ;;
    --record-action)   RECORD_ACTION="$2"; shift 2 ;;
    --recorders)       RECORDERS="$2"; shift 2 ;;
    --record-outcomes) RECORD_OUTCOMES="$2"; shift 2 ;;
    --record-attrs)    RECORD_ATTRS="$2"; shift 2 ;;
    --record-ms)       RECORD_MS="$2"; shift 2 ;;
    --budget-ms)   BUDGET_MS="$2"; shift 2 ;;
    --openclaw)    OPENCLAW="$2"; shift 2 ;;
    --apply)       APPLY=1; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$BUDGET_MS" in
  ''|*[!0-9]*) echo "--budget-ms takes milliseconds: $BUDGET_MS" >&2; exit 2 ;;
esac
[ "$BUDGET_MS" -gt 0 ] || { echo "--budget-ms must be positive" >&2; exit 2; }

# A window that is not a whole number of days would reach the config as a value the plugin reads as
# "off", which is a digest that looks wired and never fires. Refused here, where it can still be
# spelled correctly.
if [ -n "$DIGEST_DAYS" ]; then
  case "$DIGEST_DAYS" in
    ''|*[!0-9]*) echo "--digest-days takes whole days: $DIGEST_DAYS" >&2; exit 2 ;;
  esac
  [ "$DIGEST_DAYS" -gt 0 ] || {
    echo "--digest-days must be positive; pass no --digest-days to turn the digest off" >&2
    exit 2
  }
fi

# Not `whole days`-shaped and it reaches the config as a value the plugin reads as "unset", which is
# an allowance that looks configured and silently is not. Zero is accepted and means zero.
case "$ACTOR_ROWS" in
  ''|*[!0-9]*) echo "--actor-rows takes a whole number of rows: $ACTOR_ROWS" >&2; exit 2 ;;
esac
[ "$ACTOR_ROWS" -le "$MAX_RECORDS" ] || {
  echo "--actor-rows $ACTOR_ROWS would be the whole page of $MAX_RECORDS; the actor is background" >&2
  exit 2
}

# A reader that is not there would be wired anyway and fail open on every turn — quietly enough that
# a deployment could run for weeks believing it had recall. Refused here instead.
command -v "$READER" >/dev/null 2>&1 || [ -x "$READER" ] || {
  echo "read tool not found: $READER — install it, or pass --reader" >&2
  exit 1
}

# A spec directory missing its two files would be wired anyway, and every turn would then spend a
# lookup on a reader that refuses the read. Refused here, where it can still be spelled correctly.
if [ -n "$SPEC_DIR" ]; then
  for file in entities.yaml extractors.yaml; do
    [ -f "$SPEC_DIR/$file" ] || {
      echo "--spec-dir $SPEC_DIR holds no $file — it names the deployment's spec directory" >&2
      exit 1
    }
  done
fi

# A map that does not parse would reach the config as something the plugin reads as "this agent is
# unmapped", which is a lookup that looks wired and asks about no actor on every turn — the exact
# failure this flag exists to end, restored by a typo. Refused here, where it can still be spelled
# correctly, and the writer names are checked for the two shapes that cannot survive an argument list.
ACTORS_JSON=""
if [ -n "$ACTORS" ]; then
  seen=""
  IFS=','
  for pair in $ACTORS; do
    unset IFS
    case "$pair" in
      *=*) ;;
      *) echo "--actors takes agent=writer pairs: $pair" >&2; exit 2 ;;
    esac
    id="${pair%%=*}"
    writer="${pair#*=}"
    [ -n "$id" ] && [ -n "$writer" ] || {
      echo "--actors pair names no agent or no writer: $pair" >&2; exit 2
    }
    case "$writer" in
      -*) echo "--actors writer '$writer' would be read as a flag in the reader's argv" >&2; exit 2 ;;
      *=*) echo "--actors pair has more than one '=': $pair" >&2; exit 2 ;;
    esac
    # Both halves land inside a JSON string this script writes by hand, and both are identifiers on
    # either side of a socket. Anything outside that alphabet is a quoting bug waiting to happen.
    case "$id$writer" in
      *[!A-Za-z0-9_.-]*) echo "--actors names are identifiers: $pair" >&2; exit 2 ;;
    esac
    case " $seen " in
      *" $id "*) echo "--actors names agent '$id' twice" >&2; exit 2 ;;
    esac
    seen="$seen $id"
    ACTORS_JSON="$ACTORS_JSON${ACTORS_JSON:+, }\"$id\": \"$writer\""
    IFS=','
  done
  unset IFS
fi

case "$RECORD_MS" in
  ''|*[!0-9]*) echo "--record-ms takes milliseconds: $RECORD_MS" >&2; exit 2 ;;
esac
[ "$RECORD_MS" -gt 0 ] || { echo "--record-ms must be positive" >&2; exit 2; }

# Both halves of the write path or neither. An action with no recorder writes nowhere and looks
# wired; a recorder with no action would write an action the store never declared, which is a
# rejected write on every turn rather than a quiet one. Refused here, where either is a typo.
if [ -n "$RECORD_ACTION" ] && [ -z "$RECORDERS" ]; then
  echo "--record-action names an action with no recorder to write it; pass --recorders too" >&2
  exit 2
fi
if [ -n "$RECORDERS" ] && [ -z "$RECORD_ACTION" ]; then
  echo "--recorders names recorders with no action to write; pass --record-action too" >&2
  exit 2
fi

# agent id -> recorder path. A recorder that is not there would be wired anyway and fail on every
# turn, quietly enough that a deployment could believe it had coverage; refused, as the reader is.
RECORDERS_JSON=""
if [ -n "$RECORDERS" ]; then
  seen=""
  IFS=','
  for pair in $RECORDERS; do
    unset IFS
    case "$pair" in
      *=*) ;;
      *) echo "--recorders takes agent=path pairs: $pair" >&2; exit 2 ;;
    esac
    id="${pair%%=*}"
    tool="${pair#*=}"
    [ -n "$id" ] && [ -n "$tool" ] || {
      echo "--recorders pair names no agent or no recorder: $pair" >&2; exit 2
    }
    case "$id" in
      *[!A-Za-z0-9_.-]*) echo "--recorders agent ids are identifiers: $id" >&2; exit 2 ;;
    esac
    # A path is not an identifier, so it is checked for the two things that cannot survive: a quote
    # would break the JSON this script writes by hand, and a leading dash would be read as a flag.
    case "$tool" in
      -*) echo "--recorders path '$tool' would be read as a flag" >&2; exit 2 ;;
      *[\"\\]*) echo "--recorders path '$tool' cannot be written into JSON here" >&2; exit 2 ;;
    esac
    command -v "$tool" >/dev/null 2>&1 || [ -x "$tool" ] || {
      echo "record tool not found: $tool — install it, or fix --recorders" >&2; exit 1
    }
    case " $seen " in
      *" $id "*) echo "--recorders names agent '$id' twice" >&2; exit 2 ;;
    esac
    seen="$seen $id"
    RECORDERS_JSON="$RECORDERS_JSON${RECORDERS_JSON:+, }\"$id\": [\"$tool\"]"
    IFS=','
  done
  unset IFS
fi

# The outcome and attribute maps. Both are small `key=value` lists whose keys this script knows and
# whose values are the deployment's own words, so an unknown key is refused rather than written into
# a config where the plugin would ignore it and nothing would say so.
# The answer goes in this variable rather than on stdout: a refusal inside a command substitution
# would exit only the subshell it ran in, leaving the caller to carry on with an empty map and no
# sign that anything was wrong. A function that refuses has to be able to stop the script.
PAIRS_JSON=""
pairs_json() {
  flag="$1"
  allowed="$2"
  raw="$3"
  empty_ok="$4"
  PAIRS_JSON=""
  seen=""
  IFS=','
  for pair in $raw; do
    unset IFS
    case "$pair" in
      *=*) ;;
      *) echo "$flag takes key=value pairs: $pair" >&2; exit 2 ;;
    esac
    key="${pair%%=*}"
    value="${pair#*=}"
    case " $allowed " in
      *" $key "*) ;;
      *) echo "$flag does not know '$key'; it knows$allowed" >&2; exit 2 ;;
    esac
    if [ -z "$value" ] && [ "$empty_ok" != yes ]; then
      echo "$flag gives '$key' no value" >&2
      exit 2
    fi
    case "$value" in
      *[!A-Za-z0-9_.-]*) echo "$flag value for '$key' is not a declared name: $value" >&2; exit 2 ;;
    esac
    case " $seen " in
      *" $key "*) echo "$flag names '$key' twice" >&2; exit 2 ;;
    esac
    seen="$seen $key"
    PAIRS_JSON="$PAIRS_JSON${PAIRS_JSON:+, }\"$key\": \"$value\""
    IFS=','
  done
  unset IFS
}

# An empty value is a deployment saying its action has no word for that outcome, so those turns are
# not recorded at all. That is a real setting here, which is why this map accepts one and the other
# does not: an attribute key with no value is a key nobody named.
RECORD_OUTCOMES_JSON=""
if [ -n "$RECORD_OUTCOMES" ]; then
  pairs_json --record-outcomes "success failure" "$RECORD_OUTCOMES" yes
  RECORD_OUTCOMES_JSON="$PAIRS_JSON"
fi
RECORD_ATTRS_JSON=""
if [ -n "$RECORD_ATTRS" ]; then
  pairs_json --record-attrs "channel recalled" "$RECORD_ATTRS" no
  RECORD_ATTRS_JSON="$PAIRS_JSON"
fi

[ -n "$SOCKET" ] || SOCKET="$HOME/.local/state/harness/sockets/$AGENT.read.sock"

# The documented resolution order, replicated rather than asked of the CLI so this gives the same
# answer when the CLI is not installed — and because the answer decides whether we refuse.
if [ -z "$CONFIG" ]; then
  if [ -n "${OPENCLAW_CONFIG_PATH:-}" ]; then
    CONFIG="$OPENCLAW_CONFIG_PATH"
  elif [ -n "${OPENCLAW_STATE_DIR:-}" ]; then
    CONFIG="$OPENCLAW_STATE_DIR/openclaw.json"
  else
    CONFIG="$HOME/.openclaw/openclaw.json"
  fi
fi

# No config means no deployment to wire. Writing one from here would produce a file the harness has
# never validated, so this stops instead.
[ -f "$CONFIG" ] || {
  echo "no harness config at $CONFIG — set it up first, or pass --config" >&2
  exit 1
}

# A plugin directory holding some other plugin is not ours to overwrite.
manifest="$PLUGIN_DIR/openclaw.plugin.json"
if [ -f "$manifest" ]; then
  found="$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -1)"
  [ "$found" = "$PLUGIN_ID" ] || {
    echo "$PLUGIN_DIR already holds the plugin '$found' — pass a different --plugin-dir" >&2
    exit 1
  }
fi

mkdir -p "$PLUGIN_DIR"
for file in openclaw.plugin.json package.json index.mjs; do
  install -m 0644 "$here/memory-plugin/$file" "$PLUGIN_DIR/$file"
done
echo "→ installed the recall plugin in $PLUGIN_DIR"

# Two budgets, and the wider one is the host's. The host does default this hook to 15s, but 15s in
# front of a reply is a conversation that looks hung; and the host's own timeout says only that a
# hook failed, where the plugin's says whether the store was quiet or the reader was.
HOST_MS=$((BUDGET_MS * 2))
# The same nesting for the record hook, and it is the looser of the two on purpose: this one runs
# behind the reply, so a generous bound costs a conversation nothing. The host's own default for it
# is 30s, which is fine and is not what lands — the plugin's shorter bound is, so the answer an
# operator reads names the recorder rather than saying only that a hook failed.
RECORD_HOST_MS=$((RECORD_MS * 2))

# The socket is on the command line here, unlike the write path, which takes it from the environment.
# The reason there was an allowlist pattern that would have had to match a socket path; nothing
# matches this argv, and a plugin spawning from the gateway's own environment is a weaker thing to
# depend on than an argument this file wrote.
# What the turn can say about itself, emitted only when it was named. An empty string in the config
# would read as configured and behave as unconfigured, and the plugin's load-time note — which is how
# an operator finds out — would then be saying the opposite of what the file appears to say.
TURN=""
if [ -n "$THREAD_KIND" ]; then
  TURN="$TURN
          \"threadEntity\": \"$THREAD_KIND\","
fi
if [ -n "$SPEC_DIR" ]; then
  TURN="$TURN
          \"specDir\": \"$SPEC_DIR\","
fi
if [ -n "$ACTORS_JSON" ]; then
  TURN="$TURN
          \"actors\": {$ACTORS_JSON},
          \"actorMaxRecords\": $ACTOR_ROWS,"
fi
# The digest's three settings travel together or not at all: two caps with no window to apply them to
# would read as a configured digest that never fires, which is the shape of wiring nobody debugs.
if [ -n "$DIGEST_DAYS" ]; then
  TURN="$TURN
          \"digestDays\": $DIGEST_DAYS,
          \"digestMaxRecords\": $DIGEST_MAX_RECORDS,
          \"digestMaxChars\": $DIGEST_MAX_CHARS,"
fi
# The write half, and it travels as one piece for the same reason the digest does: an action with no
# recorder, or recorders with no action, is wiring that looks live and writes nothing. The two maps
# below it are optional and each is emitted only when named, because an empty object in the config
# would read as configured and behave as absent.
if [ -n "$RECORD_ACTION" ] && [ -n "$RECORDERS_JSON" ]; then
  TURN="$TURN
          \"recordAction\": \"$RECORD_ACTION\",
          \"record\": {$RECORDERS_JSON},
          \"recordTimeoutMs\": $RECORD_MS,"
  if [ -n "$RECORD_OUTCOMES_JSON" ]; then
    TURN="$TURN
          \"recordOutcomes\": {$RECORD_OUTCOMES_JSON},"
  fi
  if [ -n "$RECORD_ATTRS_JSON" ]; then
    TURN="$TURN
          \"recordAttrs\": {$RECORD_ATTRS_JSON},"
  fi
fi

# `allowConversationAccess` is emitted unconditionally, and it is not a widening this script chose:
# the harness classes every hook that sees a turn as conversation access, and a plugin it did not
# ship itself may register one only where this says so. Both of this plugin's hooks are on that list.
# Without it the host refuses them at registration with a warning naming this exact setting, which is
# the right way for the grant to work — and the wrong thing to leave for an operator to discover from
# a plugin that loaded, said nothing, and recalled nothing.
fragment="$PLUGIN_DIR/config-fragment.json"
cat > "$fragment" <<JSON
{
  "plugins": {
    "load": {
      "paths": ["$PLUGIN_DIR"]
    },
    "slots": {
      "memory": "$PLUGIN_ID"
    },
    "entries": {
      "$PLUGIN_ID": {
        "enabled": true,
        "hooks": {
          "timeouts": {
            "before_prompt_build": $HOST_MS,
            "agent_end": $RECORD_HOST_MS
          },
          "allowConversationAccess": true
        },
        "config": {
          "read": ["$READER", "bundle", "--socket", "$SOCKET"],$TURN
          "timeoutMs": $BUDGET_MS,
          "maxRecords": $MAX_RECORDS,
          "maxChars": $MAX_CHARS
        }
      },
      "active-memory": {
        "enabled": false
      }
    }
  }
}
JSON
echo "→ wrote $fragment"

if [ "$APPLY" -eq 1 ]; then
  command -v "$OPENCLAW" >/dev/null 2>&1 || [ -x "$OPENCLAW" ] || {
    echo "harness CLI not found: $OPENCLAW — needed for --apply, or merge by hand" >&2
    exit 1
  }
  # A patch replaces an array rather than extending it, so an existing load path would be dropped.
  # Refused rather than merged blind: this harness's other plugin — the guard — lives on that list,
  # and dropping it would unwire the tool policy to install recall.
  existing="$("$OPENCLAW" config get plugins.load.paths 2>/dev/null || true)"
  case "$existing" in
    ''|'[]'|'null'|*"$PLUGIN_DIR"*) ;;
    *)
      echo "plugins.load.paths already holds entries a patch would replace:" >&2
      echo "  $existing" >&2
      echo "add \"$PLUGIN_DIR\" to that array by hand, then re-run without --apply" >&2
      exit 1
      ;;
  esac
  "$OPENCLAW" config patch --file "$fragment" --dry-run
  "$OPENCLAW" config patch --file "$fragment"
  echo "→ merged $fragment into $CONFIG"
else
  cat <<MERGE

$CONFIG was left alone. Merge the fragment with one validated write:

  $OPENCLAW config patch --file "$fragment" --dry-run   # schema-checks it, writes nothing
  $OPENCLAW config patch --file "$fragment"

A patch replaces arrays rather than extending them, and the guard plugin lives on the same list.
Check it first, and add the directory to what is already there instead if that list is not empty:

  $OPENCLAW config get plugins.load.paths
MERGE
fi

cat <<NEXT

What the fragment claims, so it can be checked rather than trusted:

  plugins.slots.memory = $PLUGIN_ID   one plugin owns memory, and naming it disables the built-in
  plugins.entries.active-memory.enabled = false   nothing else may inject memory into a prompt

A bundle composes context out of entities and an actor, and this plugin can state neither on its own.
With none of them named, every turn asks an empty question and gets an empty answer that looks exactly
like a quiet store. Three settings close that:

  config.threadEntity = ${THREAD_KIND:-<unset>}   a turn inside a thread looks that thread up
  config.specDir      = ${SPEC_DIR:-<unset>}   the turn's message is read for entities too
  config.actors       = ${ACTORS:-<unset>}   whose activity a turn asks about
  config.actorMaxRecords = $ACTOR_ROWS   how much of the page that activity may take

The third is the one that cannot be guessed and must not be. The host's agent id — \`main\`, \`pr\` — is
not the name the store filed that agent's records under: a record carries whatever caller its record
socket signed as, which on a deployment generating writers from a keyring is a different string. Send
the agent id and the bundle asks about a writer nothing was ever written by, and answers an empty page
every turn. So the map is stated rather than derived, and an agent this map leaves out asks about no
actor at all and says so in the log — a narrower question, honestly asked, instead of a silent zero.

The fourth is what keeps the third from swallowing the page. A bundle fills its entities first and
gives the actor the rest, so an actor that matches takes everything the keys left — which on a turn
naming no key is all of it, and the same rows arrive whatever was asked. The actor is read separately
and bounded to \`config.actorMaxRecords\` rows behind an answer, and is not read at all on a turn whose
entities matched nothing: there is no answer there for background to be background to.

Read the names off the keyring rather than off a pattern, and check one before trusting the map:

  $READER bundle --socket "$SOCKET" --actor <writer> --limit 3

And one setting that is not about the turn at all:

  config.digestDays   = ${DIGEST_DAYS:-<unset>}   the turn that opens a session also carries a
  date-grouped digest of what was recorded in that many days — but only where the turn's own
  entities found nothing, so the composed answer to the question keeps the space whenever there is
  one. A ranked search hit does not: by its own heading it may not be about the message at all. Nor
  does the actor's background page, which is why it is never read on a turn with no answer under it.

A digest says who acted, when, and what they referenced. It cannot say what any of it was about:
records have bodies, and by design no read here returns one. Turn it on where that is a table of
contents an agent can follow up with a read of its own, and leave it off where the records are all
one shape and the block would read as noise.

The second needs the reader to support \`--infer-entities\`; check with:

  $READER bundle --dry-run --infer-entities "${SPEC_DIR:-/path/to/spec}" --infer-from "ticket PROJ-42"

Expect a request whose \`entity\` parameter names what that sentence mentions. Inference at read time
is only a lookup key: a key guessed wrongly matches nothing, and the confidence a stored reference
needs before it reaches a bundle is untouched by it.

Neither is decoration. Leave the slot unset and the built-in memory plugin fills it on a first-come
basis, and two things answer "what do we remember" from two stores.

Check the reader answers before restarting anything, with no model in the loop:

  $READER bundle --socket "$SOCKET" --limit 3

Expect JSON with a records array — an empty one is a valid answer and exits 0. Exit 9 means the
socket is not being served; check the sidecar for agent "$AGENT" is running and that this is the
\`.read.sock\` rather than the record socket beside it.

Then restart the gateway and confirm the plugin loaded and took the slot:

  $OPENCLAW plugins doctor
  $OPENCLAW plugins inspect $PLUGIN_ID --runtime --json
NEXT
