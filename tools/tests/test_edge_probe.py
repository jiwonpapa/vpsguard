"""EDGE-013/EDGE-015 loopback probe regression tests."""

from __future__ import annotations

import unittest

from tools.vpsguard_harness.edge_probe import (
    ProbeResponse,
    assert_capacity_responses,
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
