"""Repository governance gate contracts."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.governance import (
    GovernanceError,
    validate_requirements,
    validate_rustdoc,
)


class GovernanceTests(unittest.TestCase):
    """Governance parsing should be typed and independent from GNU text tools."""

    def test_rustdoc_gate_detects_missing_module_docs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "crates/demo/src").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["crates/demo"]\n'
                '[workspace.lints.rust]\nmissing_docs = "deny"\n',
                encoding="utf-8",
            )
            (root / "crates/demo/Cargo.toml").write_text(
                '[package]\nname = "demo"\nversion = "0.1.0"\nedition = "2024"\n'
                '[lints]\nworkspace = true\n',
                encoding="utf-8",
            )
            source = root / "crates/demo/src/lib.rs"
            source.write_text("pub fn undocumented() {}\n", encoding="utf-8")

            with self.assertRaises(GovernanceError) as raised:
                validate_rustdoc(root)

            self.assertEqual(raised.exception.code, "RUSTDOC_CONTRACT_FAILED")
            self.assertIn("missing module rustdoc", raised.exception.cause)

            source.write_text("//! Demo module.\n\npub fn documented() {}\n", encoding="utf-8")
            validate_rustdoc(root)

    def test_requirements_gate_matches_contract_trace_and_registry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            product = root / "specs/product"
            product.mkdir(parents=True)
            implementation = root / "implementation.txt"
            automated = root / "automated.txt"
            implementation.write_text("implemented\n", encoding="utf-8")
            automated.write_text("passed\n", encoding="utf-8")
            (product / "06-requirements-contracts.md").write_text(
                "| `NFR-009` | language boundary | gate |\n", encoding="utf-8"
            )
            (product / "07-verification-traceability.md").write_text(
                "| `NFR-009` | test | report |\n", encoding="utf-8"
            )
            (product / "verification-status.tsv").write_text(
                "NFR-009|AUTO_PASS|implementation.txt|automated.txt|-\n",
                encoding="utf-8",
            )

            summary = validate_requirements(root, release=False)

            self.assertEqual(summary.total, 1)
            self.assertEqual(summary.auto_pass, 1)

            (product / "07-verification-traceability.md").write_text(
                "no mapped requirement\n", encoding="utf-8"
            )
            with self.assertRaises(GovernanceError) as raised:
                validate_requirements(root, release=False)
            self.assertEqual(raised.exception.code, "REQUIREMENTS_TRACE_MISMATCH")

    def test_requirements_gate_rejects_evidence_outside_repository(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            product = root / "specs/product"
            product.mkdir(parents=True)
            automated = root / "automated.txt"
            automated.write_text("passed\n", encoding="utf-8")
            (product / "06-requirements-contracts.md").write_text(
                "| `NFR-009` | language boundary | gate |\n", encoding="utf-8"
            )
            (product / "07-verification-traceability.md").write_text(
                "| `NFR-009` | test | report |\n", encoding="utf-8"
            )
            (product / "verification-status.tsv").write_text(
                f"NFR-009|AUTO_PASS|{automated.resolve()}|automated.txt|-\n",
                encoding="utf-8",
            )

            with self.assertRaises(GovernanceError) as raised:
                validate_requirements(root, release=False)

            self.assertEqual(raised.exception.code, "VERIFICATION_EVIDENCE_INVALID")
            self.assertIn("missing implementation evidence", raised.exception.cause)


if __name__ == "__main__":
    unittest.main()
