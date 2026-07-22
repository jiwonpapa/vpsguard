"""Commit requirement traceability contract tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.commit_contract import (
    CommitContractError,
    CommitRecord,
    resolve_revision_range,
    validate_commit_records,
)


class CommitContractTests(unittest.TestCase):
    """Every authored change commit must carry a requirement identifier."""

    def test_accepts_requirement_ids_in_subject_or_body(self) -> None:
        commits = (
            CommitRecord("a" * 40, 1, "test(edge): ratchet headers\n\nRequirements: EDGE-003"),
            CommitRecord("b" * 40, 1, "fix(NFR-011): preserve coverage floor"),
        )

        summary = validate_commit_records(commits)

        self.assertEqual(summary.checked, 2)

    def test_rejects_any_authored_commit_without_requirement_id(self) -> None:
        commits = (
            CommitRecord("a" * 40, 1, "feat(edge): covered\n\nRequirements: EDGE-003"),
            CommitRecord("b" * 40, 1, "refactor: unexplained change"),
        )

        with self.assertRaises(CommitContractError) as raised:
            validate_commit_records(commits)

        self.assertEqual(raised.exception.code, "COMMIT_REQUIREMENT_ID_MISSING")
        self.assertIn("bbbbbbbbbbbb", raised.exception.cause)

    def test_ignores_generated_merge_commits(self) -> None:
        summary = validate_commit_records(
            (CommitRecord("c" * 40, 2, "Merge branch 'main' into feature"),)
        )

        self.assertEqual(summary.checked, 0)
        self.assertEqual(summary.merges_skipped, 1)

    def test_resolves_complete_pull_request_and_push_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            base = "a" * 40
            head = "b" * 40
            event.write_text(
                json.dumps({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}),
                encoding="utf-8",
            )
            self.assertEqual(
                resolve_revision_range(
                    {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event)}
                ),
                f"{base}..{head}",
            )

            event.write_text(json.dumps({"before": base, "after": head}), encoding="utf-8")
            self.assertEqual(
                resolve_revision_range(
                    {"GITHUB_EVENT_NAME": "push", "GITHUB_EVENT_PATH": str(event)}
                ),
                f"{base}..{head}",
            )

    def test_rejects_invalid_event_sha(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            event.write_text(
                json.dumps(
                    {
                        "pull_request": {
                            "base": {"sha": "not-a-sha"},
                            "head": {"sha": "b" * 40},
                        }
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(CommitContractError) as raised:
                resolve_revision_range(
                    {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event)}
                )

            self.assertEqual(raised.exception.code, "COMMIT_EVENT_INVALID")


if __name__ == "__main__":
    unittest.main()
