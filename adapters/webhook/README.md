# webhook adapter

```sh
PORT=8099 HARNESS_SOCKET=/run/harness/ingress.sock ./adapter.py
curl -X POST localhost:8099 -H 'X-Delivery-Id: abc123' -d 'summarise order ord-91h2'
```

Standard library only — deploying it is copying one file.

It prefers the source's `X-Delivery-Id` for `envelope_id`, because a retry carries the same value and
that is what makes deduplication work. Without one it digests the body, which is stable for an
identical payload but cannot tell a genuine resubmission from a retry. Returns `503` when ingress is
down so the source retries, rather than `500` which many senders treat as final.
