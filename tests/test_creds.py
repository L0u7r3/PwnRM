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
        result = CredsModule().run(shell, ["vault"])
        script = script_from(shell)
        self.assertEqual(result["selected"], ["vault"])
        self.assertIn("$doVault = $true", script)
        self.assertIn("$doDpapi = $false", script)
        self.assertIn("vaultcmd.exe", script)

    def test_valid_decrypt_uses_localfree_for_crypt32_output(self):
        shell = shell_mock()
        blob = base64.b64encode(b"not-a-real-dpapi-blob").decode()
        result = CredsModule().run(shell, ["decrypt", blob])
        script = script_from(shell)
        self.assertEqual(result["status"], "completed")
        self.assertIn(f"$decryptBlob = '{blob}'", script)
        self.assertIn("LocalFree(output.pbData)", script)
        self.assertNotIn("FreeHGlobal(output.pbData)", script)

    def test_invalid_decrypt_input_is_rejected(self):
        shell = shell_mock()
        for args in (["decrypt"], ["decrypt", "not base64"], ["--unknown"]):
            with self.subTest(args=args):
                shell.reset_mock()
                result = CredsModule().run(shell, args)
                self.assertEqual(result["status"], "error")
                shell.run_with_interrupt.assert_not_called()

    def test_lsa_dump_stages_unique_minidump_and_reports_hash(self):
        shell = shell_mock()
        result = CredsModule().run(shell, ["lsa"])
        script = script_from(shell)
        self.assertEqual(result["selected"], ["lsa"])
        self.assertIn("$doLsa = $true", script)
        self.assertIn("pwnrm_lsass_{0}.dmp", script)
        self.assertIn("comsvcs.dll", script)
        self.assertIn("Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256", script)
        self.assertIn("PPL/EDR may block access", script)
        self.assertIn("$ErrorActionPreference = 'Stop'", script)
        self.assertIn("-ErrorAction Continue", script)
        self.assertIn("& $rundll32 $comsvcsEntry MiniDump", script)
        self.assertIn("MiniDump worker timed out after 180 seconds", script)
        self.assertNotIn("Start-Process -FilePath $rundll32", script)

    def test_lsa_output_requires_lsa_and_absolute_safe_path(self):
        for args in (
            ["--lsa-output"],
            ["--lsa-output", "relative.dmp"],
            ["--lsa-output", "C:\\Temp\\*.dmp", "lsa"],
            ["--lsa-output", "C:\\Temp\\dump.dmp"],
        ):
            with self.subTest(args=args):
                shell = shell_mock()
                result = CredsModule().run(shell, args)
                self.assertEqual(result["status"], "error")
                shell.run_with_interrupt.assert_not_called()

    def test_lsa_output_is_single_quote_escaped(self):
        shell = shell_mock()
        result = CredsModule().run(shell, ["lsa", "--lsa-output", "C:\\Temp\\operator's.dmp"])
        script = script_from(shell)
        self.assertEqual(result["status"], "completed")
        self.assertIn("$lsaOutput = 'C:\\Temp\\operator''s.dmp'", script)

    def test_legacy_dashed_modes_remain_compatible(self):
        shell = shell_mock()
        result = CredsModule().run(shell, ["--vault"])
        self.assertEqual(result["selected"], ["vault"])


if __name__ == "__main__":
    unittest.main()
