#!/usr/bin/env python3
"""HTTP adapter: receives POSTs, forwards envelopes, posts deliveries back.

Kept to the standard library so deployment is copying one file.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

SOCKET = os.environ.get("HARNESS_SOCKET", "/run/harness/ingress.sock")
SOURCE = "webhook"


def envelope_id(raw: bytes, delivery_header: str | None) -> str:
    """Derive a stable id.

    Prefer the source's own delivery identifier when it sends one: a retry carries the same value,
    which is what lets the dispatcher recognise it. Fall back to a digest of the payload, which is
    stable for an identical body but cannot distinguish a genuine duplicate submission.
    """
    if delivery_header:
        return f"{SOURCE}-{delivery_header}"
    return f"{SOURCE}-{hashlib.sha256(raw).hexdigest()[:16]}"


class Handler(BaseHTTPRequestHandler):
    """Turns one POST into one envelope."""

    def do_POST(self) -> None:  # noqa: N802 - name fixed by BaseHTTPRequestHandler
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        envelope = {
            "envelope_id": envelope_id(raw, self.headers.get("X-Delivery-Id")),
            "source": SOURCE,
            "received_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            # A source that counts its own retries is telling us dedupe matters on this request.
            "attempt": int(self.headers.get("X-Delivery-Attempt", "1")),
            "reply_to": self.headers.get("X-Reply-To"),
            "actor": self.headers.get("X-Actor"),
            "body": raw.decode("utf-8", "replace"),
            "extra": {},
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.connect(SOCKET)
                sock.sendall((json.dumps(envelope) + "\n").encode())
            self.send_response(202)
        except OSError as exc:
            # 503 rather than 500: the source should retry, and its retry will carry the same
            # delivery id, so re-running costs nothing.
            self.log_error("ingress unavailable: %s", exc)
            self.send_response(503)
        self.end_headers()

    def log_message(self, fmt: str, *args: object) -> None:
        """Log to stderr without the default timestamp noise."""
        print(f"webhook: {fmt % args}", file=__import__("sys").stderr)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8099"))
    print(f"webhook adapter listening on :{port}, ingress {SOCKET}")
    HTTPServer(("", port), Handler).serve_forever()
