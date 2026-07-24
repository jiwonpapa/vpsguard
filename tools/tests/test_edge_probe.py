"""EDGE-003/EDGE-006/EDGE-013/EDGE-015 loopback probe regression tests."""

from __future__ import annotations

import unittest

from tools.vpsguard_harness.edge_probe import (
    CHUNKED_RESPONSE_BODY,
    LARGE_RESPONSE_BYTES,
    LARGE_RESPONSE_SHA256,
    ProbeResponse,
    assert_body_policy,
    assert_capacity_responses,
    assert_streaming_responses,
    assert_timeout_policy,
    probe_common_rate_limit,
)


class EdgeProbeTests(unittest.TestCase):
    """Keep overload and common-rate assertions fail closed."""

    def test_capacity_requires_normal_and_retryable_rejection(self) -> None:
        assert_capacity_responses(
            [
                ProbeResponse(status=200, retry_after=None),
                ProbeResponse(status=503, retry_after="1"),
            ]
        )
        with self.assertRaisesRegex(AssertionError, "Retry-After"):
            assert_capacity_responses(
                [
                    ProbeResponse(status=200, retry_after=None),
                    ProbeResponse(status=503, retry_after=None),
                ]
            )

    def test_common_rate_limit_accepts_only_200_until_429(self) -> None:
        responses = iter(
            [
                ProbeResponse(status=200, retry_after=None),
                ProbeResponse(status=200, retry_after=None),
                ProbeResponse(status=429, retry_after="60"),
            ]
        )
        self.assertEqual(probe_common_rate_limit(lambda _path: next(responses)), 3)
        with self.assertRaisesRegex(AssertionError, "Retry-After"):
            probe_common_rate_limit(
                lambda _path: ProbeResponse(status=429, retry_after=None)
            )

    def test_streaming_requires_exact_large_and_chunked_payloads(self) -> None:
        assert_streaming_responses(
            ProbeResponse(
                status=200,
                retry_after=None,
                body_length=LARGE_RESPONSE_BYTES,
                body_sha256=LARGE_RESPONSE_SHA256,
            ),
            ProbeResponse.from_body(200, None, CHUNKED_RESPONSE_BODY),
        )
        with self.assertRaisesRegex(AssertionError, "large response"):
            assert_streaming_responses(
                ProbeResponse.from_body(200, None, b"truncated"),
                ProbeResponse.from_body(200, None, CHUNKED_RESPONSE_BODY),
            )
        with self.assertRaisesRegex(AssertionError, "chunked response"):
            assert_streaming_responses(
                ProbeResponse(
                    status=200,
                    retry_after=None,
                    body_length=LARGE_RESPONSE_BYTES,
                    body_sha256=LARGE_RESPONSE_SHA256,
                ),
                ProbeResponse.from_body(200, None, b"truncated"),
            )

    def test_body_policy_distinguishes_regular_and_upload_routes(self) -> None:
        assert_body_policy(
            ProbeResponse(status=413, retry_after=None),
            ProbeResponse(status=200, retry_after=None),
        )
        with self.assertRaisesRegex(AssertionError, "upload"):
            assert_body_policy(
                ProbeResponse(status=413, retry_after=None),
                ProbeResponse(status=413, retry_after=None),
            )

    def test_timeout_policy_preserves_long_upload_window(self) -> None:
        assert_timeout_policy(
            ProbeResponse(status=502, retry_after=None),
            ProbeResponse(status=200, retry_after=None),
        )
        with self.assertRaisesRegex(AssertionError, "regular"):
            assert_timeout_policy(
                ProbeResponse(status=200, retry_after=None),
                ProbeResponse(status=200, retry_after=None),
            )
