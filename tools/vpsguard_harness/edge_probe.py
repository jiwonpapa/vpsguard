"""Loopback EDGE-013/EDGE-015 concurrency and common-rate probes."""

from __future__ import annotations

import argparse
import http.client
import json
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class ProbeResponse:
    """Bounded fields retained from one loopback edge response."""

    status: int
    retry_after: str | None


def assert_capacity_responses(responses: list[ProbeResponse]) -> None:
    """Require accepted work plus fail-fast overload responses."""

    assert any(response.status == 200 for response in responses), (
        "capacity probe did not preserve any normal request"
    )
    assert any(response.status == 503 for response in responses), (
        "capacity probe did not reject overload"
    )
    assert all(response.status in {200, 503} for response in responses), (
        "capacity probe returned an unexpected status"
    )
    assert all(
        response.retry_after == "1"
        for response in responses
        if response.status == 503
    ), "capacity rejection omitted Retry-After: 1"


def probe_common_rate_limit(
    request: Callable[[str], ProbeResponse],
    *,
    max_attempts: int = 40,
) -> int:
    """Return the attempt that reaches the common 429 limit."""

    for attempt in range(1, max_attempts + 1):
        response = request("/common-rate-limit")
        if response.status == 429:
            return attempt
        assert response.status == 200, (
            f"common rate probe returned unexpected status {response.status}"
        )
    raise AssertionError("common rate limit was not reached")


class HttpsProbeClient:
    """Issue isolated HTTPS requests to a loopback edge listener."""

    def __init__(self, address: str, port: int, host: str) -> None:
        self.address = address
        self.port = port
        self.host = host
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE

    def request(self, path: str) -> ProbeResponse:
        """Return only status and Retry-After without retaining a body."""

        connection = http.client.HTTPSConnection(
            self.address,
            self.port,
            timeout=5,
            context=self.context,
        )
        try:
            connection.request(
                "GET",
                path,
                headers={"Host": self.host, "Connection": "close"},
            )
            response = connection.getresponse()
            result = ProbeResponse(
                status=response.status,
                retry_after=response.getheader("Retry-After"),
            )
            response.read()
            return result
        finally:
            connection.close()


def run_probe(client: HttpsProbeClient, evidence: Path) -> None:
    """Run concurrent capacity first, then exhaust the common request limit."""

    paths = [f"/__vpsguard_test__/slow?id={index}" for index in range(1, 7)]
    with ThreadPoolExecutor(max_workers=len(paths)) as executor:
        capacity = list(executor.map(client.request, paths))
    assert_capacity_responses(capacity)
    rate_limit_attempt = probe_common_rate_limit(client.request)
    evidence.write_text(
        json.dumps(
            {
                "capacity": [asdict(response) for response in capacity],
                "common_rate_limit_attempt": rate_limit_attempt,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    """Parse loopback listener arguments and execute the bounded probes."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    arguments = parser.parse_args(argv)
    run_probe(
        HttpsProbeClient(arguments.address, arguments.port, arguments.host),
        arguments.evidence,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
