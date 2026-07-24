"""Loopback streaming, route-budget, concurrency and common-rate probes."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

CHUNKED_RESPONSE_BODY = b"alpha\nbeta\ngamma\n"
LARGE_RESPONSE_BYTES = 2 * 1024 * 1024
LARGE_RESPONSE_PATTERN = b"vpsguard-stream\n"
LARGE_RESPONSE_SHA256 = hashlib.sha256(
    LARGE_RESPONSE_PATTERN * (LARGE_RESPONSE_BYTES // len(LARGE_RESPONSE_PATTERN))
).hexdigest()
MAX_PROBE_RESPONSE_BYTES = LARGE_RESPONSE_BYTES + 1024


@dataclass(frozen=True)
class ProbeResponse:
    """Bounded fields retained from one loopback edge response."""

    status: int
    retry_after: str | None
    body_length: int = 0
    body_sha256: str = ""

    @classmethod
    def from_body(
        cls,
        status: int,
        retry_after: str | None,
        body: bytes,
    ) -> ProbeResponse:
        """Build bounded body metadata without retaining response content."""

        return cls(
            status=status,
            retry_after=retry_after,
            body_length=len(body),
            body_sha256=hashlib.sha256(body).hexdigest(),
        )


def assert_streaming_responses(
    large: ProbeResponse,
    chunked: ProbeResponse,
) -> None:
    """Require byte-exact large and chunked responses through Edge."""

    assert (
        large.status == 200
        and large.body_length == LARGE_RESPONSE_BYTES
        and large.body_sha256 == LARGE_RESPONSE_SHA256
    ), "large response was truncated or changed"
    assert (
        chunked.status == 200
        and chunked.body_length == len(CHUNKED_RESPONSE_BODY)
        and chunked.body_sha256 == hashlib.sha256(CHUNKED_RESPONSE_BODY).hexdigest()
    ), "chunked response was truncated or changed"


def assert_body_policy(regular: ProbeResponse, upload: ProbeResponse) -> None:
    """Require a larger upload allowance without weakening regular routes."""

    assert regular.status == 413, "regular route did not enforce its body limit"
    assert upload.status == 200, "upload route did not preserve its larger body limit"


def assert_timeout_policy(regular: ProbeResponse, upload: ProbeResponse) -> None:
    """Require the upload timeout window to exceed the regular window."""

    assert regular.status == 502, "regular route did not enforce its upstream timeout"
    assert upload.status == 200, "upload route did not preserve its longer timeout"


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
            assert response.retry_after == "60", "common 429 omitted Retry-After: 60"
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

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        body: bytes | None = None,
    ) -> ProbeResponse:
        """Return status and bounded body metadata without retaining content."""

        connection = http.client.HTTPSConnection(
            self.address,
            self.port,
            timeout=5,
            context=self.context,
        )
        try:
            connection.request(
                method,
                path,
                body=body,
                headers={"Host": self.host, "Connection": "close"},
            )
            response = connection.getresponse()
            payload = response.read(MAX_PROBE_RESPONSE_BYTES + 1)
            assert len(payload) <= MAX_PROBE_RESPONSE_BYTES, (
                "edge probe response exceeded the bounded capture limit"
            )
            return ProbeResponse.from_body(
                response.status,
                response.getheader("Retry-After"),
                payload,
            )
        finally:
            connection.close()


def run_probe(client: HttpsProbeClient, evidence: Path) -> None:
    """Run byte integrity, route budgets, capacity and common-rate probes."""

    large = client.request("/__vpsguard_test__/large")
    chunked = client.request("/__vpsguard_test__/chunked")
    assert_streaming_responses(large, chunked)
    request_body = b"x" * 2048
    regular_body = client.request("/regular", method="POST", body=request_body)
    upload_body = client.request("/upload", method="POST", body=request_body)
    assert_body_policy(regular_body, upload_body)
    regular_timeout = client.request("/__vpsguard_test__/timeout")
    upload_timeout = client.request("/upload/__vpsguard_test__/timeout")
    assert_timeout_policy(regular_timeout, upload_timeout)
    paths = [f"/__vpsguard_test__/slow?id={index}" for index in range(1, 7)]
    with ThreadPoolExecutor(max_workers=len(paths)) as executor:
        capacity = list(executor.map(client.request, paths))
    assert_capacity_responses(capacity)
    rate_limit_attempt = probe_common_rate_limit(client.request)
    evidence.write_text(
        json.dumps(
            {
                "streaming": {
                    "large": asdict(large),
                    "chunked": asdict(chunked),
                },
                "route_body_policy": {
                    "regular": asdict(regular_body),
                    "upload": asdict(upload_body),
                },
                "route_timeout_policy": {
                    "regular": asdict(regular_timeout),
                    "upload": asdict(upload_timeout),
                },
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
