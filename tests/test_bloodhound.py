"""Tests for bounded AD graph collection method selection."""

import base64
import re
import unittest
from unittest.mock import MagicMock

from pwnrm.modules.bloodhound import BloodhoundModule


def invoke(args):
    shell = MagicMock()
    shell.run_with_interrupt.return_value = False
    result = BloodhoundModule().run(shell, args)
    command = shell.run_with_interrupt.call_args.args[0]
    encoded = re.search(r"FromBase64String\('([^']+)'\)", command).group(1)
    return result, base64.b64decode(encoded).decode("utf-16le")


class TestBloodhoundModule(unittest.TestCase):
    def test_group_selector_only_enables_groups(self):
        result, script = invoke(["-c", "Group"])
        self.assertEqual(result["methods"], ["group"])
        self.assertIn("$doGroups = $true", script)
        self.assertIn("$doSessions = $false", script)

    def test_default_expands_dconly_and_session(self):
        result, script = invoke([])
        self.assertEqual(result["methods"], ["computer", "group", "session", "user"])
        self.assertIn("not a BloodHound CE import archive", script)

    def test_unimplemented_method_is_rejected(self):
        shell = MagicMock()
        result = BloodhoundModule().run(shell, ["-c", "LocalAdmin"])
        self.assertEqual(result["status"], "error")
        shell.run_with_interrupt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
