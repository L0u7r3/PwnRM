"""Tests for Kerberos feature selection and dMSA schema coverage."""

import base64
import re
import unittest
from unittest.mock import MagicMock

from pwnrm.modules.kerberos import KerberosModule


def get_script(args):
    shell = MagicMock()
    shell.run_with_interrupt.return_value = False
    result = KerberosModule().run(shell, args)
    command = shell.run_with_interrupt.call_args.args[0]
    encoded = re.search(r"FromBase64String\('([^']+)'\)", command).group(1)
    return result, base64.b64decode(encoded).decode("utf-16le")


class TestKerberosModule(unittest.TestCase):
    def test_selector_controls_sections(self):
        result, script = get_script(["--dmsa", "--diamond"])
        self.assertEqual(result["selected"], ["--diamond", "--dmsa"])
        self.assertIn("$doDmsa = $true", script)
        self.assertIn("$doDiamond = $true", script)
        self.assertIn("$doRoast = $false", script)

    def test_server_2025_dmsa_schema_is_queried(self):
        _, script = get_script(["--dmsa"])
        self.assertIn("objectClass=msDS-DelegatedManagedServiceAccount", script)
        self.assertIn("msDS-ManagedAccountPrecededByLink", script)
        self.assertIn("msDS-DelegatedMSAState", script)

    def test_unknown_option_is_rejected(self):
        shell = MagicMock()
        result = KerberosModule().run(shell, ["--fake"])
        self.assertEqual(result["status"], "error")
        shell.run_with_interrupt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
