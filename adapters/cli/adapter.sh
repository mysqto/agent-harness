#!/usr/bin/env sh
# The smallest adapter that satisfies the contract: stdin in, stdout out.
#
# Each input line becomes one envelope. The id is derived from the line's content and position
# rather than from a clock, so re-running the same input is idempotent — which is what lets this be
# used in tests and replays without generating duplicate tasks.
set -eu

SOCKET="${HARNESS_SOCKET:-/run/harness/ingress.sock}"
SOURCE="cli"

line_no=0
while IFS= read -r body; do
  line_no=$((line_no + 1))
  # Content-addressed id: same input, same id, however many times it is fed in.
  digest=$(printf '%s\n%s' "$line_no" "$body" | cksum | cut -d' ' -f1)
  printf '{"envelope_id":"%s-%s","source":"%s","received_at":"%s","attempt":1,' \
    "$SOURCE" "$digest" "$SOURCE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '"reply_to":"stdout","actor":"local","body":%s,"extra":{}}\n' \
    "$(printf '%s' "$body" | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/')"
done | {
  if [ -S "$SOCKET" ]; then
    # Deliveries come back on the same connection and go straight to stdout.
    nc -U "$SOCKET"
  else
    echo "adapter: no ingress socket at $SOCKET; printing envelopes instead" >&2
    cat
  fi
}
