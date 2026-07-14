#!/usr/bin/env python3
"""Loopback-only HTTP origin used by the VPSGuard integration harness."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    """Return a bounded echo of proxy-owned headers."""

    def do_GET(self):  # noqa: N802
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
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format, *_args):
        """Keep the test output deterministic."""


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 18081), Handler).serve_forever()
