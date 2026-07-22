"""Harness language ownership policy contracts."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.vpsguard_harness.policy import PolicyError, validate_language_policy


class LanguagePolicyTests(unittest.TestCase):
    """Python and Shell boundaries must fail closed."""

    def test_rejects_shell_true_and_hardcoded_root_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(Path(directory))
            package = root / "tools/vpsguard_harness"
            (package / "bad.py").write_text(
                "import subprocess\n"
                "subprocess.run('systemctl restart demo', shell=True)\n"
                "target = '/etc/demo.conf'\n",
                encoding="utf-8",
            )

            with self.assertRaises(PolicyError) as raised:
                validate_language_policy(root)

            message = raised.exception.cause
            self.assertIn("shell=True", message)
            self.assertIn("protected production path", message)

    def test_rejects_new_large_shell_and_accepts_thin_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(Path(directory))
            wrapper = root / "scripts/new-wrapper.sh"
            wrapper.write_text("#!/usr/bin/env bash\n" + "true\n" * 41, encoding="utf-8")

            with self.assertRaises(PolicyError) as raised:
                validate_language_policy(root)
            self.assertIn("new Shell wrapper exceeds 40 lines", raised.exception.cause)

            wrapper.write_text("#!/usr/bin/env bash\nset -euo pipefail\ntrue\n", encoding="utf-8")
            validate_language_policy(root)

    def test_checks_every_name_in_a_multi_import(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self._root(Path(directory))
            package = root / "tools/vpsguard_harness"
            (package / "bad_import.py").write_text(
                "import json, requests\n",
                encoding="utf-8",
            )

            with self.assertRaises(PolicyError) as raised:
                validate_language_policy(root)

            self.assertIn("non-stdlib Python dependency requests", raised.exception.cause)

    @staticmethod
    def _root(root: Path) -> Path:
        (root / "scripts").mkdir(parents=True)
        (root / "tools/vpsguard_harness").mkdir(parents=True)
        (root / "tools/harness-shell-baseline.json").write_text(
            json.dumps({"schema_version": 1, "files": {}}), encoding="utf-8"
        )
        (root / "tools/vpsguard_harness/good.py").write_text(
            '"""Safe fixture."""\nfrom pathlib import Path\nROOT = Path.cwd()\n',
            encoding="utf-8",
        )
        return root


if __name__ == "__main__":
    unittest.main()
