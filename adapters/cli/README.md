# cli adapter

Reads one message per line from stdin, emits envelopes, prints deliveries.

```sh
echo "summarise order ord-91h2" | HARNESS_SOCKET=/run/harness/ingress.sock ./adapter.sh
```

With no socket present it prints the envelopes it would have sent, which makes it a way to inspect
the contract without running anything.

`envelope_id` is content-addressed — derived from the line and its position, not from a clock — so
feeding the same input twice produces the same ids and the dispatcher treats the second run as a
redelivery rather than new work. That is the behaviour you want in a test and the behaviour you want
in a replay.
