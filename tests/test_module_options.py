"""Regression tests for module option parsing and generated PowerShell."""

import base64
import re
import unittest
from unittest.mock import MagicMock

from pwnrm.modules.entra import EntraModule
from pwnrm.modules.evasion import EvasionModule
from pwnrm.modules.laps import LAPSModule
from pwnrm.modules.lateral import LateralModule


def decode_payload(command: str) -> str:
    encoded = re.search(r"FromBase64String\('([^']+)'\)", command).group(1)
    return base64.b64decode(encoded).decode("utf-16le")


def fake_shell():
    shell = MagicMock()
    shell.run_with_interrupt = MagicMock(return_value=False)
    shell.write_line = MagicMock()
    shell.write_info = MagicMock()
    shell.write_warning = MagicMock()
    shell.write_error = MagicMock()
    return shell


class TestEvasionOptions(unittest.TestCase):
    def test_edr_only_does_not_patch_memory(self):
        shell = fake_shell()
        result = EvasionModule().run(shell, ["edr"])
        self.assertEqual(result["status"], "completed")
        commands = [call.args[0] for call in shell.run_with_interrupt.call_args_list]
        self.assertEqual(len(commands), 1)
        self.assertIn("EDR / AV", commands[0])
        self.assertNotIn("VirtualProtect", commands[0])

    def test_etw_only_uses_architecture_correct_stubs(self):
        shell = fake_shell()
        EvasionModule().run(shell, ["etw"])
        commands = "\n".join(call.args[0] for call in shell.run_with_interrupt.call_args_list)
        self.assertNotIn("AmsiScanBuffer", commands)
        self.assertIn("[IntPtr]::Size -eq 8", commands)
        self.assertIn("[byte[]](0x33,0xc0,0xc3)", commands)
        self.assertIn("0xc2,20,0x00", commands)
        self.assertIn("0xc2,28,0x00", commands)

    def test_unknown_option_is_rejected(self):
        shell = fake_shell()
        result = EvasionModule().run(shell, ["--nope"])
        self.assertEqual(result["status"], "error")
        shell.run_with_interrupt.assert_not_called()


class TestLateralOptions(unittest.TestCase):
    def test_custom_subnet_ports_and_auth_probe_are_applied(self):
        shell = fake_shell()
        result = LateralModule().run(
            shell,
            ["--subnet", "192.0.2.0/30", "--ports", "5985,135,5985", "--probe-auth"],
        )
        self.assertEqual(result["targets"], 2)
        self.assertEqual(result["ports"], [5985, 135])
        script = decode_payload(shell.run_with_interrupt.call_args.args[0])
        self.assertIn("192.0.2.0/30", script)
        self.assertIn("$ports = @(5985, 135)", script)
        self.assertIn("$probeAuth = $true", script)
        self.assertIn("192.0.2.1\n192.0.2.2", base64.b64decode(
            re.search(r"UTF8.GetString\(\[Convert\]::FromBase64String\('([^']+)'\)", script).group(1)
        ).decode())

    def test_invalid_or_oversized_scans_are_rejected(self):
        for args in (
            ["--subnet", "not-a-network"],
            ["--subnet", "10.0.0.0/8"],
            ["--ports", "0,70000"],
            ["--ports", "abc"],
            ["--unknown"],
        ):
            with self.subTest(args=args):
                shell = fake_shell()
                result = LateralModule().run(shell, args)
                self.assertEqual(result["status"], "error")
                shell.run_with_interrupt.assert_not_called()


class TestEntraOptions(unittest.TestCase):
    def test_default_is_join_state_only(self):
        shell = fake_shell()
        result = EntraModule().run(shell, [])
        script = decode_payload(shell.run_with_interrupt.call_args.args[0])
        self.assertFalse(result["full_scan"])
        self.assertIn("$fullScan = $false", script)

    def test_full_scan_walks_cloud_cache_locations(self):
        shell = fake_shell()
        result = EntraModule().run(shell, ["full"])
        script = decode_payload(shell.run_with_interrupt.call_args.args[0])
        self.assertTrue(result["full_scan"])
        self.assertIn("$fullScan = $true", script)
        self.assertIn("msal_token_cache.bin", script)
        self.assertIn("Microsoft.AAD.BrokerPlugin", script)


class TestLapsAllOption(unittest.TestCase):
    def test_all_reports_computers_without_readable_laps(self):
        shell = fake_shell()
        result = LAPSModule().run(shell, ["all"])
        script = decode_payload(shell.run_with_interrupt.call_args.args[0])
        self.assertTrue(result["all_computers"])
        self.assertIn("if ($true -and -not $legacyPwd", script)
        self.assertIn("NO READABLE LAPS", script)
        self.assertIn("MODERN LAPS ENCRYPTED DSRM", script)


if __name__ == "__main__":
    unittest.main()
