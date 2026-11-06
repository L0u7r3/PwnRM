"""Regression tests for jobs, ticket inventory, capabilities, and Ligolo management."""

import hashlib
import io
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pwnrm.core.capabilities import get_capability
from pwnrm.core.jobs import JobRegistry
from pwnrm.core.ligolo import LigoloAssetManager
from pwnrm.core.tickets import TicketManager
from pwnrm.shell.pwnshell import PwnShell


class TestJobRegistry(unittest.TestCase):
    def test_process_jobs_persist_and_resolve_by_id_or_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = JobRegistry(Path(directory), "DC01")
            record = registry.register(
                kind="ligolo",
                name="agent.exe",
                mode="process",
                remote_id="remote-one",
                pid=4242,
            )
            self.assertIs(registry.resolve(record.job_id[:4]), record)
            self.assertIs(registry.resolve("4242"), record)
            state_file = Path(directory) / "jobs" / "registry.json"
            self.assertEqual(stat.S_IMODE(state_file.stat().st_mode), 0o600)

            reloaded = JobRegistry(Path(directory), "dc01")
            restored = reloaded.resolve(record.job_id)
            self.assertEqual(restored.pid, 4242)
            self.assertEqual(restored.status, "running")

    def test_runspace_job_is_marked_orphaned_after_registry_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = JobRegistry(Path(directory), "dc01")
            record = registry.register(
                kind="noconsolation-native",
                name="tool.exe",
                mode="runspace",
                remote_id="abc123",
            )
            reloaded = JobRegistry(Path(directory), "dc01")
            self.assertEqual(reloaded.resolve(record.job_id).status, "orphaned")

    def test_target_selection_isolated_jobs_between_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = JobRegistry(Path(directory), "dc01")
            first = registry.register(kind="ligolo", name="one", mode="process", pid=1)
            registry.select_target("FS01")
            second = registry.register(kind="ligolo", name="two", mode="process", pid=2)
            self.assertEqual([item.job_id for item in registry.list()], [second.job_id])
            registry.select_target("dc01")
            self.assertEqual([item.job_id for item in registry.list()], [first.job_id])


class _Principal:
    def __init__(self, text):
        self.text = text

    def prettyPrint(self):
        return self.text.encode()


class TestTicketManager(unittest.TestCase):
    @staticmethod
    def _cache(server="cifs/dc01@LAB.LOCAL"):
        credential = {
            "client": _Principal("Administrator@LAB.LOCAL"),
            "server": _Principal(server),
            "key": {"keytype": 18},
            "tktflags": 0x40A10000,
            "time": {
                "authtime": 1_700_000_000,
                "starttime": 1_700_000_000,
                "endtime": 1_700_003_600,
                "renew_till": 1_700_086_400,
            },
        }
        return SimpleNamespace(
            principal=_Principal("Administrator@LAB.LOCAL"),
            credentials=[credential],
        )

    def test_ccache_inventory_exposes_service_and_lifetime(self):
        with tempfile.NamedTemporaryFile() as handle, patch(
            "pwnrm.core.tickets.CCache.loadFile",
            return_value=self._cache(),
        ):
            info = TicketManager().inspect(handle.name)
        self.assertEqual(info.principal, "Administrator@LAB.LOCAL")
        self.assertFalse(info.has_tgt)
        self.assertEqual(info.tickets[0].server, "cifs/dc01@LAB.LOCAL")
        self.assertEqual(info.tickets[0].enctype, "aes256_cts_hmac_sha1_96")
        self.assertNotEqual(info.tickets[0].end_time, "-")

    def test_service_ticket_only_cache_cannot_be_renewed(self):
        with tempfile.NamedTemporaryFile() as handle, patch(
            "pwnrm.core.tickets.CCache.loadFile",
            return_value=self._cache(),
        ):
            with self.assertRaisesRegex(ValueError, "no TGT"):
                TicketManager().renew(handle.name)

    def test_tgt_renewal_uses_kinit_without_a_shell(self):
        cache = self._cache("krbtgt/LAB.LOCAL@LAB.LOCAL")
        with (
            tempfile.NamedTemporaryFile() as handle,
            patch("pwnrm.core.tickets.CCache.loadFile", return_value=cache),
            patch("pwnrm.core.tickets.shutil.which", return_value="/usr/bin/kinit"),
            patch("pwnrm.core.tickets.subprocess.run", return_value=SimpleNamespace(returncode=0, stderr="", stdout="")) as run,
        ):
            renewed = TicketManager().renew(handle.name)
        self.assertTrue(renewed.has_tgt)
        self.assertEqual(run.call_args.args[0][:3], ["/usr/bin/kinit", "-R", "-c"])
        self.assertFalse(run.call_args.kwargs["check"])


class _Response:
    def __init__(self, *, payload=None, body=b""):
        self.payload = payload
        self.body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload

    def iter_content(self, _size):
        yield self.body


class TestLigoloAssets(unittest.TestCase):
    def test_verified_release_is_extracted_without_archive_paths(self):
        archive_io = io.BytesIO()
        agent = b"MZ" + b"agent-payload"
        with zipfile.ZipFile(archive_io, "w") as bundle:
            bundle.writestr("release/agent.exe", agent)
        archive = archive_io.getvalue()
        checksum = f"{hashlib.sha256(archive).hexdigest()}  ligolo-ng_agent_1.2.3_windows_amd64.zip\n".encode()
        release = {
            "tag_name": "v1.2.3",
            "assets": [
                {"name": "ligolo-ng_agent_1.2.3_windows_amd64.zip", "browser_download_url": "https://example.test/agent"},
                {"name": "ligolo-ng_1.2.3_checksums.txt", "browser_download_url": "https://example.test/checksums"},
            ],
        }
        session = MagicMock()
        session.get.side_effect = [
            _Response(payload=release),
            _Response(body=archive),
            _Response(body=checksum),
        ]
        with tempfile.TemporaryDirectory() as directory:
            manager = LigoloAssetManager(Path(directory), session=session)
            result = manager.fetch(version="1.2.3", architecture="amd64")
            destination = Path(result["path"])
            self.assertEqual(destination.read_bytes(), agent)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            self.assertEqual(manager.latest_installed("amd64"), str(destination))

    def test_profiles_validate_and_preserve_tls_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = LigoloAssetManager(Path(directory))
            profile = manager.save_profile(
                "lab",
                "10.10.14.2:11601",
                fingerprint="ab" * 32,
            )
            self.assertEqual(profile["fingerprint"], "ab" * 32)
            self.assertEqual(manager.get_profile("lab")["connect"], "10.10.14.2:11601")
            with self.assertRaisesRegex(ValueError, "either"):
                manager.save_profile("bad", "host:1", ignore_cert=True, fingerprint="ab" * 32)


class TestCapabilityAndShellDispatch(unittest.TestCase):
    def test_persistent_only_capability_reflects_backend(self):
        capability = get_capability("!noconsolation")
        self.assertTrue(capability.available(persistent=True))
        self.assertFalse(capability.available(persistent=False))

    def test_ticket_use_requires_reconnect_and_becomes_selected_cache(self):
        shell = object.__new__(PwnShell)
        shell.ticket_mgr = MagicMock()
        shell.ticket_mgr.inspect.return_value = SimpleNamespace(path="/tmp/new.ccache")
        shell._selected_ccache = ""
        shell.write_info = MagicMock()
        shell.write_warning = MagicMock()
        shell.write_error = MagicMock()
        with patch.dict(os.environ, {}, clear=False):
            result = shell._ticket_dispatch("use /tmp/new.ccache")
            self.assertEqual(os.environ["KRB5CCNAME"], "FILE:/tmp/new.ccache")
        self.assertTrue(result["reconnect_required"])
        self.assertEqual(shell._active_ccache_path(), "/tmp/new.ccache")

    def test_ligolo_start_updates_tracked_job_kind(self):
        shell = object.__new__(PwnShell)
        shell.runspace = SimpleNamespace(persistent=True)
        record = SimpleNamespace(
            job_id="deadbeef",
            metadata={"process_start_ticks": 638980000000000000},
        )
        shell.job_registry = MagicMock()
        shell.job_registry.resolve.return_value = record
        shell.noconsolation = MagicMock(return_value={"status": "completed", "job_id": "deadbeef"})
        shell._ligolo_specs = {}
        result = shell.ligolo("start --agent agent.exe -connect 127.0.0.1:11601 -ignore-cert")
        self.assertEqual(result["kind"], "ligolo")
        shell.job_registry.update.assert_called_once()
        self.assertEqual(
            shell.job_registry.update.call_args.kwargs["metadata"]["process_start_ticks"],
            638980000000000000,
        )
        forwarded = shell.noconsolation.call_args.args[0]
        self.assertIn("--detached native agent.exe", forwarded)
        self.assertIn("-connect 127.0.0.1:11601", forwarded)

    def test_process_job_refuses_to_stop_a_reused_pid(self):
        shell = object.__new__(PwnShell)
        record = SimpleNamespace(
            job_id="deadbeef",
            pid=4242,
            mode="process",
            metadata={"process_start_ticks": 638980000000000000},
        )
        shell.run_sync = MagicMock(return_value="REUSED\n")
        shell.job_registry = MagicMock()
        shell.write_info = MagicMock()
        shell.write_error = MagicMock()
        result = shell._stop_job(record)
        self.assertEqual(result["status"], "error")
        self.assertIn("different process", result["error"])
        shell.job_registry.update.assert_called_once()

    def test_process_job_stop_suppresses_wait_boolean_output(self):
        shell = object.__new__(PwnShell)
        record = SimpleNamespace(
            job_id="deadbeef",
            pid=4242,
            mode="process",
            metadata={"process_start_ticks": 638980000000000000},
        )
        shell.run_sync = MagicMock(return_value="STOPPED\n")
        shell.job_registry = MagicMock()
        shell.write_info = MagicMock()
        shell.write_error = MagicMock()
        result = shell._stop_job(record)
        self.assertEqual(result["status"], "completed")
        script = shell.run_sync.call_args.args[0]
        self.assertIn("[void]$p.WaitForExit(3000)", script)


if __name__ == "__main__":
    unittest.main()
