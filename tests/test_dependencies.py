"""Dependency and authentication-backend regression tests."""

import hashlib
import importlib
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from spnego import KerberosCCache

from pwnrm.core.api import argument_parser, create_transport
from pwnrm.core.credentials import KrbCredential, NTCredential, TransportError
from pwnrm.core.runspace import Runspace
from pwnrm.core.spnego import SPNEGOProxyNTLM
from pwnrm.core.transports import (
    BasicTransport,
    CredSSPTransport,
    KerberosTransport,
    SPNEGOTransport,
    _build_encrypted_body,
    _unwrap_encrypted_body,
)


class TestAuthenticationDependencies(unittest.TestCase):
    def test_exec_method_defaults_to_auto_and_accepts_all_backends(self):
        parser = argument_parser()
        self.assertEqual(parser.parse_args(["host"]).exec_method, "auto")
        for method in ("winrm", "wmiexec", "dcomexec", "atexec", "smbexec", "psexec"):
            with self.subTest(method=method):
                self.assertEqual(
                    parser.parse_args(["--exec-method", method, "host"]).exec_method,
                    method,
                )

    def test_complete_auth_stack_is_installed(self):
        for module_name in ("gssapi", "krb5", "requests_credssp"):
            with self.subTest(module=module_name):
                self.assertIsNotNone(importlib.import_module(module_name))

    def test_transport_factory_is_lazy(self):
        args = argument_parser().parse_args([
            "-d", "LAB.LOCAL", "-u", "user01", "-p", "password",
            "srv01.lab.local",
        ])
        with patch.object(SPNEGOTransport, "_send") as send:
            transport = create_transport(args)
        self.assertIsInstance(transport, SPNEGOTransport)
        send.assert_not_called()
        self.assertTrue(transport.session.verify)

    def test_tls_verification_can_be_explicitly_disabled(self):
        args = argument_parser().parse_args([
            "--no-ssl-verify", "-u", "user01", "-p", "password",
            "https://srv01.lab.local:5986",
        ])
        self.assertFalse(create_transport(args).session.verify)

    def test_invalid_port_and_timeout_are_rejected_by_parser(self):
        parser = argument_parser()
        for argv in (["--port", "0", "host"], ["--port", "70000", "host"], ["--timeout", "0", "host"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                parser.parse_args(argv)

    def test_invalid_nt_hash_is_rejected(self):
        for value in ("not-a-hash", "aa:bb", "a" * 33, "a" * 32 + ":" + "z" * 32):
            args = argument_parser().parse_args(["-u", "user01", "-H", value, "host"])
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "NT hash"):
                create_transport(args)

    def test_conflicting_authentication_modes_are_rejected(self):
        parser = argument_parser()
        for argv in (
            ["--pfx", "client.pfx", "-k", "host"],
            ["-k", "--credssp", "host"],
            ["--pfx", "client.pfx", "--credssp", "host"],
        ):
            with self.subTest(argv=argv), self.assertRaisesRegex(ValueError, "choose only one"):
                create_transport(parser.parse_args(argv))

    def test_hash_is_rejected_for_kerberos_credssp_and_certificate_auth(self):
        nt_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
        parser = argument_parser()
        cases = (
            ["-k", "-H", nt_hash, "host"],
            ["--credssp", "-u", "user", "-p", "password", "-H", nt_hash, "host"],
            ["--pfx", "client.pfx", "-H", nt_hash, "host"],
        )
        for argv in cases:
            with self.subTest(argv=argv), self.assertRaisesRegex(ValueError, "hash|CredSSP"):
                create_transport(parser.parse_args(argv))

    def test_lm_nt_hash_is_accepted_and_normalized(self):
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"
        nt_hash = "31D6CFE0D16AE931B73C59D7E0C089C0"
        args = argument_parser().parse_args(["-u", "user01", "-H", f"{lm_hash}:{nt_hash}", "host"])
        transport = create_transport(args)
        self.assertEqual(transport.creds.nt_hash, nt_hash.lower())

    def test_pfx_defaults_to_https(self):
        args = argument_parser().parse_args(["--pfx", "client.pfx", "host"])
        with patch("pwnrm.core.api.load_pfx", return_value=("cert.pem", "key.pem")):
            transport = create_transport(args)
        self.assertEqual(transport.url, "https://host:5986/wsman")

    def test_ntlm_domain_and_password_reach_pypsrp(self):
        transport = SPNEGOTransport(
            "http://srv01.lab.local:5985/wsman",
            NTCredential("LAB.LOCAL", "user01", "password"),
        )
        runspace = Runspace(transport)
        session = runspace._wsman.transport._build_session()
        self.assertEqual(session.auth.username, r"LAB.LOCAL\user01")
        self.assertEqual(session.auth.password, "password")

    def test_pass_the_hash_is_normalized_for_pyspnego(self):
        nt_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"
        transport = SPNEGOTransport(
            "http://srv01.lab.local:5985/wsman",
            NTCredential("LAB", "user01", nt_hash=nt_hash),
        )
        runspace = Runspace(transport)
        session = runspace._wsman.transport._build_session()
        self.assertEqual(
            session.auth.password,
            f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}",
        )

    def test_kerberos_ccache_reaches_pyspnego(self):
        ticket = SimpleNamespace(
            service_principal=SimpleNamespace(components=["TERMSRV", "DC01"]),
        )
        creds = KrbCredential(
            "LAB.LOCAL", "user01", ticket, object(),
            ccache="FILE:/tmp/user01.ccache",
        )
        runspace = Runspace(
            KerberosTransport("http://srv01.lab.local:5985/wsman", creds)
        )
        session = runspace._wsman.transport._build_session()
        self.assertIsInstance(session.auth.username, KerberosCCache)
        self.assertEqual(session.auth.username.ccache, "FILE:/tmp/user01.ccache")
        self.assertEqual(session.auth.auth_provider, "kerberos")
        self.assertEqual(session.auth.service, "TERMSRV")
        self.assertEqual(session.auth.hostname_override, "DC01.")

    def test_credssp_backend_can_be_built(self):
        transport = CredSSPTransport(
            "https://srv01.lab.local:5986/wsman",
            NTCredential("LAB", "user01", "password"),
        )
        runspace = Runspace(transport)
        session = runspace._wsman.transport._build_session()
        self.assertEqual(type(session.auth).__module__, "requests_credssp.credssp")
        with self.assertRaisesRegex(TransportError, "use Runspace"):
            transport.send(b"<soap/>")

    def test_basic_backend_can_be_built(self):
        transport = BasicTransport(
            "https://srv01.lab.local:5986/wsman",
            NTCredential("LAB", "user01", "password"),
        )
        runspace = Runspace(transport)
        session = runspace._wsman.transport._build_session()
        self.assertEqual(session.auth.username, r"LAB\user01")


class TestSPNEGORegression(unittest.TestCase):
    def test_base_transport_rejects_http_errors(self):
        transport = BasicTransport(
            "http://srv01.lab.local:5985/wsman",
            NTCredential("LAB", "user01", "password"),
        )
        with patch.object(transport, "_send", return_value=MagicMock(status_code=500)):
            with self.assertRaisesRegex(TransportError, "HTTP 500"):
                transport.send(b"<soap/>")

    def test_direct_kerberos_send_fails_explicitly_before_uninitialized_wrap(self):
        creds = KrbCredential("LAB", "user01", object(), object(), ccache="FILE:/tmp/cache")
        transport = KerberosTransport("http://srv01.lab.local:5985/wsman", creds)
        transport.proxy = SimpleNamespace(complete=False)
        with self.assertRaisesRegex(TransportError, "use Runspace"):
            transport.send(b"<soap/>")

    def test_encrypted_multipart_preserves_binary_signature_and_payload(self):
        signature = b"\x00\xffsignature"
        ciphertext = b"\x80\x00ciphertext"
        plaintext = b"<s:Envelope/>"
        body = _build_encrypted_body(
            "application/HTTP-SPNEGO-session-encrypted",
            plaintext,
            signature,
            ciphertext,
        )
        self.assertIn(signature, body)
        self.assertIn(ciphertext, body)
        self.assertNotIn(repr(signature).encode(), body)

        proxy = MagicMock()
        proxy.unwrap.return_value = plaintext
        self.assertEqual(_unwrap_encrypted_body(body, "Encrypted Boundary", proxy), plaintext)
        proxy.unwrap.assert_called_once_with(signature, ciphertext)

    def test_proxy_constructor_uses_credentials_object(self):
        response = MagicMock(status_code=200)
        transport = SPNEGOTransport(
            "http://srv01.lab.local:5985/wsman",
            NTCredential("LAB", "user01", "password"),
        )
        with patch.object(transport, "_send", return_value=response):
            transport._auth()
        self.assertIsInstance(transport.proxy, SPNEGOProxyNTLM)
        self.assertEqual(transport.proxy.creds.username, "user01")

    def test_https_channel_binding_uses_binary_certificate_digest(self):
        certificate = b"test DER certificate"
        cert_hash = hashlib.sha256(certificate).digest()
        app_data = b"tls-server-end-point:" + cert_hash
        expected = hashlib.md5(
            bytes(16) + struct.pack("<I", len(app_data)) + app_data
        ).digest()
        response = MagicMock(status_code=200)
        transport = SPNEGOTransport(
            "https://srv01.lab.local:5986/wsman",
            NTCredential("LAB", "user01", "password"),
        )
        with (
            patch("pwnrm.core.transports.get_server_certificate", return_value=certificate),
            patch.object(transport, "_send", return_value=response),
        ):
            transport._auth()
        self.assertEqual(transport.proxy.gss_bindings, expected)

    def test_credssp_no_longer_calls_proxy_with_invalid_signature(self):
        response = MagicMock(headers={})
        transport = CredSSPTransport(
            "https://srv01.lab.local:5986/wsman",
            NTCredential("LAB", "user01", "password"),
        )
        with patch.object(transport, "_send", return_value=response):
            with self.assertRaisesRegex(TransportError, "no negoToken"):
                transport._auth()


if __name__ == "__main__":
    unittest.main()
