#!/usr/bin/env python3
"""Loopback-only HTTP origin used by the VPSGuard integration harness."""

import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SLOW_RESPONSE_SECONDS = 0.1
TIMEOUT_RESPONSE_SECONDS = 0.5
LARGE_RESPONSE_BYTES = 2 * 1024 * 1024
LARGE_RESPONSE_PATTERN = b"vpsguard-stream\n"
CHUNKED_RESPONSE_PARTS = (b"alpha\n", b"beta\n", b"gamma\n")


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
        if self.path.endswith("/__vpsguard_test__/timeout"):
            time.sleep(TIMEOUT_RESPONSE_SECONDS)
        if self.path == "/__vpsguard_test__/large":
            self._send_large_response()
            return
        if self.path == "/__vpsguard_test__/chunked":
            self._send_chunked_response()
            return
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

    def _send_large_response(self):
        """Stream a deterministic two-MiB response without one large write."""

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(LARGE_RESPONSE_BYTES))
        self.end_headers()
        repeats = LARGE_RESPONSE_BYTES // len(LARGE_RESPONSE_PATTERN)
        for offset in range(0, repeats, 1024):
            count = min(1024, repeats - offset)
            self.wfile.write(LARGE_RESPONSE_PATTERN * count)

    def _send_chunked_response(self):
        """Emit a real HTTP/1.1 chunked response for proxy streaming checks."""

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        for part in CHUNKED_RESPONSE_PARTS:
            self.wfile.write(f"{len(part):x}\r\n".encode())
            self.wfile.write(part)
            self.wfile.write(b"\r\n")
        self.wfile.write(b"0\r\n\r\n")

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
