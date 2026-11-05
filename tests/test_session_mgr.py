"""
tests.test_session_mgr — Unit tests for multi-session management & encrypted persistence
"""

import tempfile
import time
import os
import unittest
from pathlib import Path
from pwnrm.core.session_mgr import SessionManager, SessionNode


class MockRunspace:
    def __init__(self):
        self.closed = False

    def run_command(self, cmd):
        yield {"stdout": f"executed: {cmd}"}

    def __exit__(self, *args):
        self.closed = True


class SlowRunspace(MockRunspace):
    def run_command(self, cmd):
        time.sleep(0.15)
        yield {"stdout": f"executed: {cmd}"}


class ErrorRecordRunspace(MockRunspace):
    def run_command(self, cmd):
        yield {"error": "remote failure"}


class TestSessionManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.mgr = SessionManager(base_dir=Path(self.temp_dir.name))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_register_and_switch(self):
        r1 = MockRunspace()
        node1 = self.mgr.register_session(r1, None, {"host": "dc01.corp.local", "user": "Admin"})
        self.assertEqual(node1.session_id, 0)
        self.assertEqual(self.mgr.current_session_id, 0)

        r2 = MockRunspace()
        node2 = self.mgr.register_session(r2, None, {"host": "srv01.corp.local", "user": "Operator"})
        self.assertEqual(node2.session_id, 1)

        self.assertTrue(self.mgr.switch_session(1))
        self.assertEqual(self.mgr.current_session_id, 1)
        self.assertEqual(self.mgr.get_current().host, "srv01.corp.local")

    def test_fan_out_execution(self):
        r1 = MockRunspace()
        r2 = MockRunspace()
        self.mgr.register_session(r1, None, {"host": "host1", "user": "u1"})
        self.mgr.register_session(r2, None, {"host": "host2", "user": "u2"})

        res = self.mgr.fan_out_exec("whoami")
        self.assertIn(0, res)
        self.assertIn(1, res)
        self.assertEqual(res[0], "[S:0 | host1] executed: whoami")
        self.assertEqual(res[1], "[S:1 | host2] executed: whoami")

    def test_fan_out_is_concurrent_and_preserves_error_records(self):
        self.mgr.register_session(SlowRunspace(), None, {"host": "slow1", "user": "u1"})
        self.mgr.register_session(SlowRunspace(), None, {"host": "slow2", "user": "u2"})
        self.mgr.register_session(ErrorRecordRunspace(), None, {"host": "broken", "user": "u3"})
        started = time.monotonic()
        result = self.mgr.fan_out_exec("hostname")
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.27)
        self.assertIn("[ERROR] remote failure", result[2])

    def test_save_and_load_encrypted(self):
        r1 = MockRunspace()
        self.mgr.register_session(r1, None, {"host": "host1", "user": "u1"})
        save_path = self.mgr.save_state("test_sessions.json")
        self.assertTrue(Path(save_path).exists())

        # Verify on-disk file is ciphertext, not plaintext JSON
        raw_on_disk = Path(save_path).read_bytes()
        self.assertFalse(raw_on_disk.startswith(b"{"))

        # Verify load_state decrypts correctly
        loaded = self.mgr.load_state("test_sessions.json")
        self.assertEqual(len(loaded.get("sessions", [])), 1)
        self.assertEqual(loaded["sessions"][0]["host"], "host1")

        self.assertTrue(self.mgr.close_session(0))
        self.assertTrue(r1.closed)
        self.assertEqual(len(self.mgr.sessions), 0)

    def test_state_filename_rejects_path_traversal(self):
        for filename in ("../sessions.json", "..\\sessions.json", "", ".."):
            with self.subTest(filename=filename):
                with self.assertRaises(ValueError):
                    self.mgr.save_state(filename)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_state_refuses_symlink_target(self):
        outside = Path(self.temp_dir.name) / "outside"
        outside.write_text("unchanged", encoding="utf-8")
        state = self.mgr.sessions_dir / "sessions.json"
        state.symlink_to(outside)
        with self.assertRaises(OSError):
            self.mgr.save_state("sessions.json")
        self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
