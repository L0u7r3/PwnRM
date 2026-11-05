"""
tests.test_vss — Unit tests for VSSModule (In-Memory Volume Shadow Copy Service)
"""

from base64 import b64decode
import re
import unittest
from unittest.mock import MagicMock
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

    def _script(self):
        cmd = self.mock_shell.run_with_interrupt.call_args[0][0]
        encoded = re.search(r"FromBase64String\('([^']+)'\)", cmd).group(1)
        return b64decode(encoded).decode("utf-16le")

    def test_module_metadata(self):
        self.assertEqual(self.mod.name, "vss")
        self.assertIn("SAM", self.mod.description)
        self.assertIn("--drive", self.mod.options)
        self.assertIn("--sam", self.mod.options)
        self.assertIn("--ntds", self.mod.options)
        self.assertIn("--clean", self.mod.options)

    def test_run_default_options(self):
        res = self.mod.run(self.mock_shell, [])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()
        self.assertIn("$requestedMode = 'auto'", self._script())

    def test_run_custom_drive_and_ntds(self):
        res = self.mod.run(self.mock_shell, ["--drive", "D:", "--ntds"])
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


if __name__ == "__main__":
    unittest.main()
