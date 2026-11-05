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
)


class TestAuthenticationDependencies(unittest.TestCase):
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

    def test_basic_backend_can_be_built(self):
        transport = BasicTransport(
            "https://srv01.lab.local:5986/wsman",
            NTCredential("LAB", "user01", "password"),
        )
        runspace = Runspace(transport)
        session = runspace._wsman.transport._build_session()
        self.assertEqual(session.auth.username, r"LAB\user01")


class TestSPNEGORegression(unittest.TestCase):
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
