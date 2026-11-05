"""
tests.test_acl — Unit tests for ACLModule (Active Directory DACL & Privilege Escalation Scout)
"""

import unittest
import base64
import re
from unittest.mock import MagicMock
from pwnrm.modules.acl import ACLModule


class TestACLModule(unittest.TestCase):
    def setUp(self):
        self.mod = ACLModule()
        self.mock_shell = MagicMock()
        self.mock_shell.run_with_interrupt = MagicMock(return_value=False)
        self.mock_shell.write_line = MagicMock()
        self.mock_shell.write_info = MagicMock()
        self.mock_shell.write_warning = MagicMock()
        self.mock_shell.write_error = MagicMock()

    def test_module_metadata(self):
        self.assertEqual(self.mod.name, "acl")
        self.assertIn("DACL", self.mod.description)
        self.assertIn("--target", self.mod.options)
        self.assertIn("--tier0", self.mod.options)

    def test_run_default(self):
        res = self.mod.run(self.mock_shell, [])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()
        cmd = self.mock_shell.run_with_interrupt.call_args[0][0]
        self.assertIn("Invoke-Expression", cmd)

    def test_run_with_target(self):
        res = self.mod.run(self.mock_shell, ["--target", "Domain Admins", "--tier0"])
        self.assertEqual(res.get("status"), "completed")
        self.mock_shell.run_with_interrupt.assert_called_once()
        cmd = self.mock_shell.run_with_interrupt.call_args[0][0]
        encoded = re.search(r"FromBase64String\('([^']+)'\)", cmd).group(1)
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertIn("$tier0Deep = $true", script)
        self.assertIn("DirectorySearcher", script)
        self.assertIn('{ "Red" } else { "Green" }', script)

    def test_target_is_not_interpolated_into_powershell(self):
        marker = "x'; Write-Host INJECTED; '"
        self.mod.run(self.mock_shell, ["--target", marker])
        cmd = self.mock_shell.run_with_interrupt.call_args[0][0]
        encoded = re.search(r"FromBase64String\('([^']+)'\)", cmd).group(1)
        script = base64.b64decode(encoded).decode("utf-16le")
        self.assertNotIn(marker, script)
        self.assertNotIn("Write-Host INJECTED", script)


if __name__ == "__main__":
    unittest.main()
