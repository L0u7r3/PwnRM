"""Tests for ADCS option handling and cautious finding semantics."""

import base64
import re
import unittest
from unittest.mock import MagicMock

from pwnrm.modules.adcs import ADCSModule


def invoke(args):
    shell = MagicMock()
    shell.run_with_interrupt.return_value = False
    result = ADCSModule().run(shell, args)
    command = shell.run_with_interrupt.call_args.args[0]
    encoded = re.search(r"FromBase64String\('([^']+)'\)", command).group(1)
    return result, base64.b64decode(encoded).decode("utf-16le")


class TestADCSModule(unittest.TestCase):
    def test_filters_are_encoded_and_applied(self):
        marker = "Tpl'; Write-Host INJECTED; '"
        result, script = invoke(["--template", marker, "--ca", "Issuing CA", "--alt", "admin@example.test"])
        self.assertEqual(result["template"], marker)
        self.assertNotIn(marker, script)
        self.assertNotIn("Write-Host INJECTED", script)
        self.assertIn("[Text.Encoding]::UTF8.GetString", script)

    def test_quick_mode_disables_acl_and_wsus(self):
        result, script = invoke(["-q"])
        self.assertTrue(result["quick"])
        self.assertFalse(result["wsus"])
        self.assertIn("$quick = $true", script)
        self.assertIn("$doWsus = $false", script)

    def test_wsus_can_be_forced_in_quick_mode(self):
        result, script = invoke(["-q", "--wsus"])
        self.assertTrue(result["wsus"])
        self.assertIn("$doWsus = $true", script)

    def test_missing_or_unknown_option_is_rejected(self):
        for args in (["--template"], ["--unknown"]):
            with self.subTest(args=args):
                shell = MagicMock()
                result = ADCSModule().run(shell, args)
                self.assertEqual(result["status"], "error")
                shell.run_with_interrupt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
