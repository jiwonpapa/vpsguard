"""Build artifact storage policy and cleanup contracts."""

from __future__ import annotations

import fcntl
import os
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.build_artifacts import (
    BuildArtifactError,
    auto_clean_build_artifacts,
    clean_build_artifacts,
    validate_build_profiles,
)


class BuildArtifactTests(unittest.TestCase):
    """Local cleanup must reclaim caches without deleting release evidence."""

    def test_cleanup_removes_regenerable_artifacts_and_preserves_release_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            (target / "debug/incremental").mkdir(parents=True)
            (target / "debug/incremental/cache.bin").write_bytes(b"d" * 4096)
            (target / "llvm-cov-target").mkdir()
            (target / "llvm-cov-target/coverage.bin").write_bytes(b"c" * 4096)
            (target / "release-bundle/demo").mkdir(parents=True)
            (target / "release-bundle/demo/checksums.txt").write_text(
                "preserve\n", encoding="utf-8"
            )
            (target / "evidence/unit").mkdir(parents=True)
            (target / "evidence/unit/result.json").write_text("{}\n", encoding="utf-8")
            (target / "operator-note").mkdir()
            (target / "operator-note/keep.txt").write_text("keep\n", encoding="utf-8")

            plan = clean_build_artifacts(root, apply=False)

            self.assertGreater(plan.reclaimable_bytes, 0)
            self.assertTrue((target / "debug").exists())
            self.assertIn("debug", plan.candidates)
            self.assertIn("release-bundle", plan.preserved)
            self.assertIn("operator-note", plan.skipped)

            result = clean_build_artifacts(root, apply=True)

            self.assertFalse((target / "debug").exists())
            self.assertFalse((target / "llvm-cov-target").exists())
            self.assertTrue((target / "release-bundle/demo/checksums.txt").exists())
            self.assertTrue((target / "evidence/unit/result.json").exists())
            self.assertTrue((target / "operator-note/keep.txt").exists())
            self.assertGreater(result.reclaimed_bytes, 0)

    def test_cleanup_rejects_a_symlinked_target_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "external"
            external.mkdir()
            (root / "target").symlink_to(external, target_is_directory=True)

            with self.assertRaises(BuildArtifactError) as raised:
                clean_build_artifacts(root, apply=True)

            self.assertEqual(raised.exception.code, "BUILD_TARGET_BOUNDARY_INVALID")

    def test_auto_cleanup_removes_only_transient_outputs_and_keeps_warm_caches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            (target / "debug").mkdir(parents=True)
            (target / "debug/cache.bin").write_bytes(b"d" * 4096)
            (target / "llvm-cov-target").mkdir()
            (target / "llvm-cov-target/coverage.bin").write_bytes(b"c" * 4096)
            (target / "tmp").mkdir()
            (target / "tmp/throwaway.bin").write_bytes(b"t" * 4096)

            result = auto_clean_build_artifacts(root, warning_bytes=1024**2)

            self.assertFalse(result.over_budget)
            self.assertTrue((target / "debug/cache.bin").exists())
            self.assertTrue((target / "llvm-cov-target/coverage.bin").exists())
            self.assertFalse((target / "tmp").exists())
            self.assertGreater(result.cleanup.reclaimed_bytes, 0)

    def test_auto_cleanup_warns_but_keeps_warm_cache_after_threshold_is_exceeded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            (target / "debug").mkdir(parents=True)
            (target / "debug/cache.bin").write_bytes(b"d" * 4096)
            (target / "release-bundle/demo").mkdir(parents=True)
            (target / "release-bundle/demo/checksums.txt").write_text(
                "preserve\n", encoding="utf-8"
            )

            result = auto_clean_build_artifacts(root, warning_bytes=1)

            self.assertTrue(result.over_budget)
            self.assertTrue((target / "debug/cache.bin").exists())
            self.assertTrue((target / "release-bundle/demo/checksums.txt").exists())

    def test_auto_cleanup_rejects_a_non_positive_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(BuildArtifactError) as raised:
                auto_clean_build_artifacts(Path(directory), warning_bytes=0)

            self.assertEqual(raised.exception.code, "BUILD_CACHE_BUDGET_INVALID")

    def test_cleanup_refuses_to_delete_an_active_cargo_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target/debug"
            target.mkdir(parents=True)
            lock_path = target / ".cargo-build-lock"
            lock_path.touch()
            with lock_path.open("rb") as lock:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

                with self.assertRaises(BuildArtifactError) as raised:
                    clean_build_artifacts(root, apply=True)

            self.assertEqual(raised.exception.code, "BUILD_TARGET_BUSY")
            self.assertTrue(target.exists())

    def test_plan_does_not_double_count_hardlinks_preserved_elsewhere(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            (target / "debug").mkdir(parents=True)
            (target / "release-bundle").mkdir()
            preserved = target / "release-bundle/shared.bin"
            preserved.write_bytes(b"x" * 4_194_304)
            os.link(preserved, target / "debug/shared.bin")

            plan = clean_build_artifacts(root, apply=False)

            self.assertLess(plan.reclaimable_bytes, 1_048_576)

    def test_build_profiles_disable_incremental_and_dependency_debug_info(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "Cargo.toml"
            manifest.write_text(
                "[profile.dev]\ndebug = 1\nincremental = false\n"
                "[profile.dev.package.\"*\"]\ndebug = false\n"
                "[profile.test]\ndebug = 1\nincremental = false\n"
                "[profile.test.package.\"*\"]\ndebug = false\n",
                encoding="utf-8",
            )

            validate_build_profiles(root)

            manifest.write_text("[profile.dev]\ndebug = 2\n", encoding="utf-8")
            with self.assertRaises(BuildArtifactError) as raised:
                validate_build_profiles(root)
            self.assertEqual(raised.exception.code, "BUILD_PROFILE_STORAGE_POLICY_FAILED")


if __name__ == "__main__":
    unittest.main()
