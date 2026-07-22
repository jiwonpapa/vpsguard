"""Honest LCOV ratchet contracts for production source files."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.coverage import CoverageError, validate_coverage


class CoverageGateTests(unittest.TestCase):
    """Coverage floors must include named production files and the workspace."""

    def test_accepts_workspace_and_file_floors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/guard-edge/src/proxy.rs"
            source.parent.mkdir(parents=True)
            source.write_text("fn proxy() {}\n", encoding="utf-8")
            lcov = root / "lcov.info"
            lcov.write_text(
                f"SF:{source}\nDA:1,1\nDA:2,0\nend_of_record\n",
                encoding="utf-8",
            )
            baseline = root / "coverage-baseline.toml"
            baseline.write_text(
                'schema_version = 1\n[workspace]\nminimum_line_percent = 50.0\n'
                '[files]\n"crates/guard-edge/src/proxy.rs" = 50.0\n',
                encoding="utf-8",
            )

            summary = validate_coverage(root, lcov, baseline)

            self.assertEqual(summary.workspace_percent, 50.0)
            self.assertEqual(summary.checked_files, 1)

    def test_rejects_a_missing_or_regressed_production_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "crates/guard-edge/src/proxy.rs"
            source.parent.mkdir(parents=True)
            source.write_text("fn proxy() {}\n", encoding="utf-8")
            lcov = root / "lcov.info"
            lcov.write_text(
                f"SF:{source}\nDA:1,0\nDA:2,0\nend_of_record\n",
                encoding="utf-8",
            )
            baseline = root / "coverage-baseline.toml"
            baseline.write_text(
                'schema_version = 1\n[workspace]\nminimum_line_percent = 0.0\n'
                '[files]\n"crates/guard-edge/src/proxy.rs" = 1.0\n'
                '"crates/guard-control/src/runtime.rs" = 1.0\n',
                encoding="utf-8",
            )

            with self.assertRaises(CoverageError) as raised:
                validate_coverage(root, lcov, baseline)

            self.assertEqual(raised.exception.code, "COVERAGE_RATCHET_FAILED")
            self.assertIn("proxy.rs", raised.exception.cause)
            self.assertIn("runtime.rs", raised.exception.cause)

    def test_rejects_sources_outside_the_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            root.mkdir()
            external = Path(directory) / "foreign.rs"
            external.write_text("fn foreign() {}\n", encoding="utf-8")
            lcov = root / "lcov.info"
            lcov.write_text(
                f"SF:{external}\nDA:1,1\nend_of_record\n",
                encoding="utf-8",
            )
            baseline = root / "coverage-baseline.toml"
            baseline.write_text(
                "schema_version = 1\n[workspace]\nminimum_line_percent = 0.0\n[files]\n",
                encoding="utf-8",
            )

            with self.assertRaises(CoverageError) as raised:
                validate_coverage(root, lcov, baseline)

            self.assertEqual(raised.exception.code, "COVERAGE_SOURCE_OUTSIDE_REPOSITORY")


if __name__ == "__main__":
    unittest.main()
