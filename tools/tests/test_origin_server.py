"""NFR-001 loopback origin transport regression tests."""

from __future__ import annotations

import importlib.util
import socket
import threading
import unittest
from pathlib import Path


def _origin_module():
    path = Path(__file__).parents[2] / "tests/fixtures/origin_server.py"
    spec = importlib.util.spec_from_file_location("vpsguard_origin_server", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load origin fixture: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OriginServerTests(unittest.TestCase):
    """The CI comparison origin must not inject delayed-ACK latency."""

    def test_accepted_connection_disables_nagle_buffering(self) -> None:
        module = _origin_module()
        server = module.NoDelayThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connected = threading.Event()

        def connect() -> None:
            client.connect(server.server_address)
            connected.set()

        thread = threading.Thread(target=connect)
        thread.start()
        connection, _address = server.get_request()
        try:
            self.assertTrue(connected.wait(timeout=1))
            self.assertNotEqual(
                connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY),
                0,
            )
        finally:
            connection.close()
            client.close()
            server.server_close()
            thread.join(timeout=1)


if __name__ == "__main__":
    unittest.main()
