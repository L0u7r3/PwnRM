"""Regression tests for CLI, interruption, transfer, and shell runtime behavior."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pwnrm.cli as cli
from pwnrm.core.runspace import Runspace
from pwnrm.core.tunnel import PortForwarder
from pwnrm.shell.ctrlc import CtrlCHandler
from pwnrm.shell.pwnshell import PwnShell


class TestRuntimeCore(unittest.TestCase):
    def test_cli_returns_failure_for_transport_setup_error(self):
        parser = MagicMock()
        parser.parse_args.return_value = SimpleNamespace(ts=False, debug=False, timeout="30")
        with (
            patch("pwnrm.cli.argument_parser", return_value=parser),
            patch("pwnrm.cli.create_transport", side_effect=ValueError("bad auth")),
            patch("builtins.print"),
        ):
            self.assertEqual(cli.main(), 1)

    def test_cli_returns_failure_for_connection_error(self):
        parser = MagicMock()
        parser.parse_args.return_value = SimpleNamespace(
            ts=False, debug=False, timeout="30", target="host", username="user"
        )
        with (
            patch("pwnrm.cli.argument_parser", return_value=parser),
            patch("pwnrm.cli.create_transport", return_value=MagicMock()),
            patch("pwnrm.cli.Runspace", side_effect=RuntimeError("offline")),
            patch("builtins.print"),
        ):
            self.assertEqual(cli.main(), 1)

    def test_runspace_interrupt_stops_active_pipeline(self):
        runspace = object.__new__(Runspace)
        runspace._active_ps = MagicMock()
        self.assertTrue(runspace.interrupt())
        runspace._active_ps.stop.assert_called_once_with()
        runspace._active_ps = None
        self.assertFalse(runspace.interrupt())

    def test_runspace_uses_interruptible_async_pipeline(self):
        class Streams:
            error = []
            warning = []
            verbose = []
            information = []
            progress = []

        class FakePowerShell:
            def __init__(self, pool):
                self.id = "pipeline-id"
                self.state = 1
                self.output = []
                self.streams = Streams()
                self.begin_options = None

            def add_script(self, command):
                return self

            def add_cmdlet(self, command):
                return self

            def add_parameter(self, command):
                return self

            def begin_invoke(self, remote_stream_options):
                self.begin_options = remote_stream_options

            def poll_invoke(self, timeout):
                self.output.append("result")
                self.state = 4

        runspace = object.__new__(Runspace)
        runspace._pool = MagicMock()
        runspace._active_ps = None
        runspace.timeout = 30
        runspace.consecutive_timeouts = 0
        runspace.max_consecutive_timeouts = 3
        runspace.command_id = None
        with patch("pwnrm.core.runspace.PowerShell", FakePowerShell):
            events = list(runspace.run_command("whoami"))
        self.assertEqual(events, [{"stdout": "result\n"}])
        self.assertIsNone(runspace._active_ps)

    def test_ctrlc_handler_invokes_interrupt_callback(self):
        installed = {}

        def fake_signal(sig, handler):
            installed[sig] = handler

        callback = MagicMock()
        with (
            patch("pwnrm.shell.ctrlc.getsignal", return_value=object()),
            patch("pwnrm.shell.ctrlc.signal", side_effect=fake_signal),
        ):
            with CtrlCHandler(on_interrupt=callback):
                handler = next(value for value in installed.values() if callable(value))
                handler(None, None)
                handler(None, None)
        callback.assert_called_once_with()

    @staticmethod
    def _bare_shell():
        shell = object.__new__(PwnShell)
        shell.stdout_log = None
        shell.socks_server = None
        shell.write_info = MagicMock()
        shell.write_warning = MagicMock()
        shell.write_error = MagicMock()
        shell.write_progress = MagicMock()
        shell.write_line = MagicMock()
        return shell

    def test_directory_download_normalizes_boolean_output(self):
        shell = self._bare_shell()

        def run_sync(command, *args, **kwargs):
            if command.startswith("Resolve-Path"):
                return "C:\\Temp\\folder\n"
            if command.startswith("Test-Path"):
                return "True\n"
            if "GetTempPath" in command:
                return "C:\\Windows\\Temp\\\n"
            return ""

        shell.run_sync = MagicMock(side_effect=run_sync)
        shell.run_with_interrupt = MagicMock(return_value=False)
        with tempfile.TemporaryDirectory() as td:
            shell.download(f'C:\\Temp\\folder "{Path(td) / "folder.zip"}"')
        commands = [call.args[0] for call in shell.run_with_interrupt.call_args_list]
        self.assertTrue(any("CreateFromDirectory" in command for command in commands))

    def test_empty_file_upload_creates_remote_temp_file(self):
        shell = self._bare_shell()
        expected = hashlib.md5(b"").hexdigest().upper()

        def run_sync(command, *args, **kwargs):
            if "GetTempPath" in command:
                return "C:\\Windows\\Temp\\\n"
            if "Get-FileHash" in command:
                return expected + "\n"
            return ""

        shell.run_sync = MagicMock(side_effect=run_sync)
        shell.run_with_interrupt = MagicMock(return_value=False)
        with tempfile.TemporaryDirectory() as td:
            empty = Path(td) / "empty.bin"
            empty.write_bytes(b"")
            shell.upload(str(empty))
        commands = [call.args[0] for call in shell.run_sync.call_args_list]
        self.assertTrue(any("WriteAllBytes" in command for command in commands))
        shell.write_error.assert_not_called()

    def test_netrun_restores_console_writers(self):
        shell = self._bare_shell()
        shell.run_with_interrupt = MagicMock(return_value=False)
        shell.netrun("https://example.invalid/tool.exe")
        commands = [call.args[0] for call in shell.run_with_interrupt.call_args_list]
        self.assertIn("$oldOut = [Console]::Out; $oldErr = [Console]::Error", commands)
        self.assertIn("[Console]::SetOut($oldOut)", commands)
        self.assertIn("[Console]::SetError($oldErr)", commands)
        self.assertNotIn("[Console]::SetOut([IO.StreamWriter]::Null)", commands)

    def test_port_forward_dispatch_can_stop_all(self):
        shell = self._bare_shell()
        shell.port_forwarder = PortForwarder()
        shell.port_forwarder.start_local_forward(0, "127.0.0.1", 11082)
        shell._portfwd_dispatch("stop all")
        self.assertEqual(shell.port_forwarder.list_forwards(), [])


if __name__ == "__main__":
    unittest.main()
