"""Regression tests for automatic WinRM/WMI/SMB execution selection."""

import os
import re
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pwnrm.core.credentials import KrbCredential, NTCredential
from pwnrm.core.remote_exec import (
    RemoteExecError,
    RemoteExecRunspace,
    _Auth,
    _Backend,
    _WMIBackend,
)
from pwnrm.core.transports import KerberosTransport, SPNEGOTransport


class _MemorySMB:
    def __init__(self, output=b"payload\nEND\n"):
        self.output = output
        self.uploads = {}
        self.deleted = []

    def putFile(self, share, path, reader):
        self.uploads[(share, path)] = reader()

    def getFile(self, share, path, callback):
        callback(self.output)

    def deleteFile(self, share, path):
        self.deleted.append((share, path))

    def logoff(self):
        pass


class _CaptureBackend(_Backend):
    name = "capture"
    required_ports = ()

    def connect(self):
        pass

    def launch(self, command):
        self.launched = command


class TestRemoteExecAuthentication(unittest.TestCase):
    def test_kerberos_short_host_is_qualified_for_impacket_spn_lookup(self):
        creds = KrbCredential(
            "INLANEFREIGHT.LOCAL",
            "Administrator",
            ticket=object(),
            tgskey=object(),
            ccache="FILE:/tmp/admin.ccache",
        )
        transport = KerberosTransport("http://DC01:5985/wsman", creds)
        auth = _Auth.from_transport(transport)
        self.assertEqual(auth.host, "dc01.INLANEFREIGHT.LOCAL")
        self.assertEqual(auth.ccache, "/tmp/admin.ccache")
        self.assertTrue(auth.kerberos)

    def test_nt_hash_is_forwarded_with_empty_lm_hash(self):
        nthash = "31d6cfe0d16ae931b73c59d7e0c089c0"
        transport = SPNEGOTransport(
            "http://dc01:5985/wsman",
            NTCredential("LAB", "operator", nt_hash=nthash),
        )
        auth = _Auth.from_transport(transport)
        self.assertEqual(auth.nthash, nthash)
        self.assertEqual(auth.lmhash, "aad3b435b51404eeaad3b435b51404ee")

    def test_ccache_environment_is_restored(self):
        auth = _Auth(
            "dc01.lab.local", "user", "", "LAB.LOCAL",
            kerberos=True, ccache="/tmp/new.ccache",
        )
        with patch.dict(os.environ, {"KRB5CCNAME": "/tmp/original.ccache"}):
            with auth.ccache_environment():
                self.assertEqual(os.environ["KRB5CCNAME"], "/tmp/new.ccache")
            self.assertEqual(os.environ["KRB5CCNAME"], "/tmp/original.ccache")


class TestRemoteExecBackend(unittest.TestCase):
    def test_staged_command_is_cleaned_even_after_execution(self):
        backend = _CaptureBackend(
            _Auth("dc01", "user", "password", "LAB"),
            timeout=3,
        )
        backend.smb = _MemorySMB()
        output = backend.execute("Write-Output 'ok'", "END")
        self.assertEqual(output, b"payload\nEND\n")
        self.assertEqual(len(backend.smb.uploads), 1)
        uploaded = next(iter(backend.smb.uploads.values()))
        self.assertTrue(uploaded.startswith(b"\xef\xbb\xbf"))
        self.assertIn("1> %SystemRoot%", backend.launched)
        self.assertNotIn("1^>", backend.launched)
        names = re.findall(r"pwnrm_([0-9a-f]{20})\.(?:ps1|out)", backend.launched)
        self.assertEqual(len(names), 2)
        self.assertEqual(names[0], names[1])
        self.assertEqual(len(backend.smb.deleted), 2)

    def test_wmi_accepts_iwbem_property_object_response(self):
        response = MagicMock()
        response.__getitem__.side_effect = TypeError("not subscriptable")
        response.getProperties.return_value = {"ReturnValue": {"value": 0}}
        backend = _WMIBackend(
            _Auth("dc01", "user", "password", "LAB"),
            timeout=3,
        )
        backend._process = MagicMock()
        backend._process.Create.return_value = response
        backend.launch("cmd.exe /c whoami")


class TestRemoteExecRunspace(unittest.TestCase):
    def _transport(self):
        return SPNEGOTransport(
            "http://dc01:5985/wsman",
            NTCredential("LAB", "operator", "password"),
        )

    def test_auto_uses_first_backend_that_executes_a_real_probe(self):
        events = []

        class Failing(_CaptureBackend):
            required_ports = ()
            def connect(self):
                events.append("first-connect")
                raise RuntimeError("blocked")
            def close(self):
                events.append("first-close")

        class Working(_CaptureBackend):
            required_ports = ()
            def connect(self):
                events.append("second-connect")
                self.smb = _MemorySMB()
            def close(self):
                events.append("second-close")

        with (
            patch("pwnrm.core.remote_exec.REMOTE_METHODS", ("first", "second")),
            patch("pwnrm.core.remote_exec._BACKENDS", {"first": Failing, "second": Working}),
        ):
            runspace = RemoteExecRunspace(self._transport(), method="auto")
            with patch.object(
                runspace,
                "_execute_wrapped",
                return_value=("__PWNRM_PROBE_OK__", True),
            ):
                with runspace as selected:
                    self.assertIs(selected, runspace)
                    self.assertEqual(runspace.backend_name, "second")
        self.assertEqual(
            events,
            ["first-connect", "first-close", "second-connect", "second-close"],
        )

    def test_no_backend_error_preserves_each_failure(self):
        class Failing(_CaptureBackend):
            required_ports = ()
            def connect(self):
                raise RuntimeError("access denied")

        with (
            patch("pwnrm.core.remote_exec.REMOTE_METHODS", ("one", "two")),
            patch("pwnrm.core.remote_exec._BACKENDS", {"one": Failing, "two": Failing}),
        ):
            runspace = RemoteExecRunspace(self._transport(), method="auto")
            with self.assertRaisesRegex(RemoteExecError, "one: access denied; two: access denied"):
                runspace.__enter__()

    def test_wrapper_hides_control_records_and_tracks_working_directory(self):
        runspace = RemoteExecRunspace(self._transport(), method="wmiexec")

        class ScriptBackend:
            def execute(self, script, footer):
                status = re.search(r"(__PWNRM_STATUS_[0-9a-f]+__=)", script).group(1)
                cwd = re.search(r"(__PWNRM_CWD_[0-9a-f]+__=)", script).group(1)
                return (
                    "visible output\r\n"
                    f"{status}ok\r\n"
                    f"{cwd}C:\\Temp\r\n"
                    f"{footer}\r\n"
                ).encode()

        runspace._backend = ScriptBackend()
        output, success = runspace._execute_wrapped("Set-Location C:\\Temp")
        self.assertEqual(output, "visible output\r\n")
        self.assertTrue(success)
        self.assertEqual(runspace._cwd, "C:\\Temp")

    def test_get_location_is_answered_without_an_extra_remote_process(self):
        runspace = RemoteExecRunspace(self._transport(), method="wmiexec")
        runspace._backend = MagicMock()
        runspace.backend_name = "wmiexec"
        runspace._cwd = "C:\\Users\\Administrator"
        events = list(runspace.run_command("Get-Location | Select -Expand Path"))
        self.assertEqual(events, [{"stdout": "C:\\Users\\Administrator\n"}])
        runspace._backend.execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
