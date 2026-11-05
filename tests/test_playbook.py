"""Regression tests for playbook validation and failure propagation."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from pwnrm.modules.playbook import PlaybookModule


def fake_shell(results):
    shell = MagicMock()
    shell.write_line = MagicMock()
    shell.write_info = MagicMock()
    shell.write_warning = MagicMock()
    shell.write_error = MagicMock()
    shell.repl = MagicMock(side_effect=results)
    return shell


class TestPlaybook(unittest.TestCase):
    def test_module_error_result_aborts_and_runs_cleanup(self):
        shell = fake_shell([{"status": "error", "error": "bad args"}, {"status": "completed"}])
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "failure.json"
            path.write_text(json.dumps([
                {"cmd": "!coerce", "cleanup_on_fail": "!portfwd stop all"},
                {"cmd": "!sysinfo"},
            ]))
            result = PlaybookModule().run(shell, ["run", "--file", str(path)])
        self.assertEqual(result, {"status": "failed", "step": 1})
        self.assertEqual(shell.repl.call_args_list[1].kwargs["inputs"], ["!portfwd stop all"])

    def test_continue_runs_cleanup_then_next_step(self):
        shell = fake_shell([
            {"status": "interrupted"},
            {"status": "completed"},
            {"status": "completed"},
            {"status": "completed"},
        ])
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "continue.json"
            path.write_text(json.dumps([
                {
                    "cmd": "!sessions",
                    "on_fail": "continue",
                    "cleanup_on_fail": ["!socks stop", "!portfwd stop all"],
                },
                {"cmd": "!sysinfo"},
            ]))
            result = PlaybookModule().run(shell, ["run", "--file", str(path)])
        self.assertEqual(result["status"], "completed")
        calls = [call.kwargs["inputs"][0] for call in shell.repl.call_args_list]
        self.assertEqual(calls, ["!sessions", "!portfwd stop all", "!socks stop", "!sysinfo"])

    def test_invalid_schema_is_rejected_before_execution(self):
        shell = fake_shell([])
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "invalid.json"
            path.write_text(json.dumps([{"cmd": "!sysinfo", "unknown": True}]))
            result = PlaybookModule().run(shell, ["run", "--file", str(path)])
        self.assertEqual(result["status"], "error")
        shell.repl.assert_not_called()

    def test_invalid_invocation_and_capture_name_are_rejected(self):
        shell = fake_shell([])
        self.assertEqual(PlaybookModule().run(shell, ["list", "extra"])["status"], "error")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "invalid-capture.json"
            path.write_text(json.dumps([{"cmd": "!sysinfo", "capture_as": "bad name"}]))
            result = PlaybookModule().run(shell, ["run", "--file", str(path)])
        self.assertEqual(result["status"], "error")
        shell.repl.assert_not_called()


if __name__ == "__main__":
    unittest.main()
