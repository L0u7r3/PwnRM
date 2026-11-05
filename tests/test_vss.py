"""
tests.test_vss — Unit tests for VSSModule (In-Memory Volume Shadow Copy Service)
"""

from base64 import b64decode
import re
import unittest
from unittest.mock import MagicMock, patch
from pwnrm.modules.vss import VSSModule


class TestVSSModule(unittest.TestCase):
    def setUp(self):
        self.mod = VSSModule()
        self.mock_shell = MagicMock()
        self.mock_shell.run_with_interrupt = MagicMock(return_value=False)
        self.mock_shell.write_line = MagicMock()
        self.mock_shell.write_info = MagicMock()
        self.mock_shell.write_warning = MagicMock()
        self.mock_shell.write_error = MagicMock()
        self.mock_shell._pse = lambda value: str(value).replace("'", "''")
        self.mock_shell._validate_remote_path = lambda value: value
        self.mock_shell.run_sync = MagicMock(side_effect=self._run_sync)
        self.mock_shell.read_remote_file = MagicMock(return_value=bytearray(b"dump"))
        self.mock_shell.delete_remote_path = MagicMock(return_value=True)
        self.mock_shell.last_run_errors = []
        self.mock_shell.target_info = {"host": "DC01"}
        self.mock_shell.loot_mgr = MagicMock()
        self.mock_shell.loot_mgr.store_artifact.return_value = "/loot/dump"
        parser = patch("pwnrm.modules.vss.parse_registry_artifacts", return_value=["secret"])
        self.parse_registry = parser.start()
        self.addCleanup(parser.stop)

    @staticmethod
    def _run_sync(command):
        if "GetTempPath" in command:
            return "C:\\Windows\\Temp\\"
        return "False"

    def _script(self):
        cmd = self.mock_shell.run_with_interrupt.call_args[0][0]
        encoded = re.search(r"FromBase64String\('([^']+)'\)", cmd).group(1)
        return b64decode(encoded).decode("utf-16le")

    def test_module_metadata(self):
        self.assertEqual(self.mod.name, "vss")
        self.assertIn("SAM", self.mod.description)
        self.assertIn("--drive", self.mod.options)
        self.assertIn("sam", self.mod.options)
        self.assertIn("ntds", self.mod.options)
        self.assertIn("--download", self.mod.options)
        self.assertIn("--clean", self.mod.options)

    def test_run_default_options(self):
        res = self.mod.run(self.mock_shell, [])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()
        self.assertIn("$requestedMode = 'auto'", self._script())

    def test_run_custom_drive_and_ntds(self):
        res = self.mod.run(self.mock_shell, ["--drive", "D:", "ntds"])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()
        script = self._script()
        self.assertIn("$drive = 'D:\\'", script)
        self.assertIn("$requestedMode = 'ntds'", script)

    def test_positional_modes_match_interactive_usage(self):
        self.mod.run(self.mock_shell, ["ntds"])
        self.assertIn("$requestedMode = 'ntds'", self._script())

        self.mock_shell.run_with_interrupt.reset_mock()
        self.mod.run(self.mock_shell, ["sam"])
        script = self._script()
        self.assertIn("$requestedMode = 'sam'", script)
        self.assertNotIn("if (false", script.lower())

    def test_conflicting_modes_are_rejected(self):
        res = self.mod.run(self.mock_shell, ["sam", "--ntds"])
        self.assertEqual(res, {"status": "error", "reason": "conflicting_modes"})
        self.mock_shell.run_with_interrupt.assert_not_called()

    def test_invalid_drive_is_rejected(self):
        res = self.mod.run(self.mock_shell, ["--drive", "C:; whoami"])
        self.assertEqual(res, {"status": "error", "reason": "invalid_drive"})
        self.mock_shell.run_with_interrupt.assert_not_called()

    def test_missing_drive_and_unknown_options_are_rejected(self):
        for args, reason in ((["--drive"], "missing_drive"), (["--nope"], "invalid_options")):
            with self.subTest(args=args):
                self.mock_shell.run_with_interrupt.reset_mock()
                res = self.mod.run(self.mock_shell, args)
                self.assertEqual(res, {"status": "error", "reason": reason})
                self.mock_shell.run_with_interrupt.assert_not_called()

    def test_failures_are_terminating_and_cleanup_is_checked(self):
        self.mod.run(self.mock_shell, ["sam"])
        script = self._script()
        self.assertIn("$ErrorActionPreference = 'Stop'", script)
        self.assertIn('6 = "insufficient storage"', script)
        self.assertIn("AvailableFreeSpace", script)
        self.assertIn('throw "SAM hive was not found', script)
        self.assertIn("$remainingShadow", script)
        self.assertIn("still exists after cleanup", script)
        self.assertIn("$stagingDir = 'C:\\Windows\\Temp\\pwnrm_vss_", script)
        self.assertNotIn("Use '!download", script)
        self.assertLess(script.index("try {"), script.index("New-Item -Path $stagingDir"))

    def test_default_parses_in_memory_and_removes_remote_staging(self):
        result = self.mod.run(self.mock_shell, ["sam"])
        self.assertEqual(result["records"], 1)
        self.assertEqual(result["downloaded"], [])
        self.parse_registry.assert_called_once()
        self.mock_shell.loot_mgr.store_artifact.assert_not_called()
        self.mock_shell.delete_remote_path.assert_called_once_with(
            self.mock_shell.delete_remote_path.call_args.args[0], recursive=True
        )

    def test_download_option_retains_raw_artifacts_but_still_cleans_remote(self):
        result = self.mod.run(self.mock_shell, ["sam", "--download"])
        self.assertEqual(result["downloaded"], ["/loot/dump", "/loot/dump"])
        self.assertEqual(self.mock_shell.loot_mgr.store_artifact.call_count, 2)
        self.mock_shell.delete_remote_path.assert_called_once()


if __name__ == "__main__":
    unittest.main()
