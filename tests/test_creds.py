"""Tests for credential module selectors and DPAPI input handling."""

import base64
import re
import unittest
from unittest.mock import MagicMock

from pwnrm.modules.creds import CredsModule


def shell_mock():
    shell = MagicMock()
    shell.run_with_interrupt.return_value = False
    return shell


def script_from(shell):
    command = shell.run_with_interrupt.call_args.args[0]
    encoded = re.search(r"FromBase64String\('([^']+)'\)", command).group(1)
    return base64.b64decode(encoded).decode("utf-16le")


class TestCredsModule(unittest.TestCase):
    def test_vault_only_selects_vault_section(self):
        shell = shell_mock()
        result = CredsModule().run(shell, ["--vault"])
        script = script_from(shell)
        self.assertEqual(result["selected"], ["--vault"])
        self.assertIn("$doVault = $true", script)
        self.assertIn("$doDpapi = $false", script)
        self.assertIn("vaultcmd.exe", script)

    def test_valid_decrypt_uses_localfree_for_crypt32_output(self):
        shell = shell_mock()
        blob = base64.b64encode(b"not-a-real-dpapi-blob").decode()
        result = CredsModule().run(shell, ["--decrypt", blob])
        script = script_from(shell)
        self.assertEqual(result["status"], "completed")
        self.assertIn(f"$decryptBlob = '{blob}'", script)
        self.assertIn("LocalFree(output.pbData)", script)
        self.assertNotIn("FreeHGlobal(output.pbData)", script)

    def test_invalid_decrypt_input_is_rejected(self):
        shell = shell_mock()
        for args in (["--decrypt"], ["--decrypt", "not base64"], ["--unknown"]):
            with self.subTest(args=args):
                shell.reset_mock()
                result = CredsModule().run(shell, args)
                self.assertEqual(result["status"], "error")
                shell.run_with_interrupt.assert_not_called()


if __name__ == "__main__":
    unittest.main()
