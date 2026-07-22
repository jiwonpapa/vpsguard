"""DET-013 official crawler pin updater regression tests."""

from __future__ import annotations

import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "update_crawler_networks.py"
SPEC = importlib.util.spec_from_file_location("update_crawler_networks", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CrawlerNetworkUpdateTests(unittest.TestCase):
    def test_normalize_validates_and_deduplicates_cidrs(self) -> None:
        feeds = {
            provider: {
                "creationTime": f"2026-07-2{index}T00:00:00Z",
                "prefixes": [
                    {"ipv4Prefix": "192.0.2.0/24"},
                    {"ipv4Prefix": "192.0.2.0/24"},
                ],
            }
            for index, provider in enumerate(MODULE.SOURCES, start=1)
        }
        result = MODULE.normalize(feeds)
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["generated_at"], "2026-07-23T00:00:00Z")
        self.assertTrue(
            all(row["cidrs"] == ["192.0.2.0/24"] for row in result["networks"])
        )

    def test_normalize_rejects_host_bits(self) -> None:
        with self.assertRaises(ValueError):
            MODULE.normalize(
                {
                    "google": {
                        "creationTime": "x",
                        "prefixes": [{"ipv4Prefix": "192.0.2.1/24"}],
                    }
                }
            )


if __name__ == "__main__":
    unittest.main()
