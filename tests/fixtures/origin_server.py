#!/usr/bin/env python3
"""Loopback-only HTTP origin used by the VPSGuard integration harness."""

import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SLOW_RESPONSE_SECONDS = 0.3


class NoDelayThreadingHTTPServer(ThreadingHTTPServer):
    """Disable delayed small-response writes in the load-test origin fixture."""

    def get_request(self):
        """Accept one connection with Nagle buffering disabled."""
        connection, address = super().get_request()
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    """Return a bounded echo of proxy-owned headers."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/__vpsguard_test__/slow"):
            time.sleep(SLOW_RESPONSE_SECONDS)
        payload = json.dumps(
            {
                "path": self.path,
                "x_forwarded_for": self.headers.get("X-Forwarded-For"),
                "x_forwarded_proto": self.headers.get("X-Forwarded-Proto"),
                "x_request_id": self.headers.get("X-Request-Id"),
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Powered-By", "fixture-runtime/1.0")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):  # noqa: N802
        """Consume the bounded integration body before returning the same echo."""
        content_length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(content_length)
        self.do_GET()

    def log_message(self, _format, *_args):
        """Keep the test output deterministic."""


if __name__ == "__main__":
    port = int(os.environ.get("VPS_GUARD_TEST_ORIGIN_PORT", "18081"))
    NoDelayThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
