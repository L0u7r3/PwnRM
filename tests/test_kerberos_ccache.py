"""Kerberos ccache parsing and S4U compatibility regressions."""

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pwnrm.core.utils import load_kerberos_ccache, prepare_kerberos_ccache


class TestKerberosCCache(unittest.TestCase):
    def test_loader_unwraps_counted_octet_string(self):
        ticket_bytes = b"DER-encoded-ticket"
        credential = MagicMock()
        credential.ticket = {"data": ticket_bytes}
        credential.__getitem__.side_effect = {
            "key": {"keytype": 23, "keyvalue": b"session-key"},
        }.__getitem__

        cache = MagicMock()
        cache.principal.realm = {"data": b"LAB.LOCAL"}
        cache.principal.components = [{"data": b"Administrator"}]
        cache.credentials = [credential]

        with (
            patch("pwnrm.core.utils.Path.exists", return_value=True),
            patch("pwnrm.core.utils.CCache.loadFile", return_value=cache),
            patch("pwnrm.core.utils.Ticket") as ticket_type,
            patch("pwnrm.core.utils.Key") as key_type,
        ):
            domain, username, ticket, key = load_kerberos_ccache("/tmp/test.ccache")

        self.assertEqual(domain, "LAB.LOCAL")
        self.assertEqual(username, "Administrator")
        self.assertIs(ticket, ticket_type.return_value)
        self.assertIs(key, key_type.return_value)
        ticket.from_asn1.assert_called_once_with(ticket_bytes)
        key_type.assert_called_once_with(23, b"session-key")

    def test_loader_prefers_matching_service_ticket_over_first_tgt(self):
        def credential(service, host, marker):
            item = MagicMock()
            item.ticket = {"data": marker.encode()}
            item.__getitem__.side_effect = {
                "server": SimpleNamespace(components=[
                    {"data": service.encode()}, {"data": host.encode()},
                ]),
                "key": {"keytype": 18, "keyvalue": marker.encode()},
            }.__getitem__
            return item

        tgt = credential("krbtgt", "LAB.LOCAL", "tgt")
        service = credential("TERMSRV", "DC01", "service")
        cache = MagicMock()
        cache.principal.realm = {"data": b"LAB.LOCAL"}
        cache.principal.components = [{"data": b"Administrator"}]
        cache.credentials = [tgt, service]

        with (
            patch("pwnrm.core.utils.Path.exists", return_value=True),
            patch("pwnrm.core.utils.CCache.loadFile", return_value=cache),
            patch("pwnrm.core.utils.Ticket") as ticket_type,
            patch("pwnrm.core.utils.Key") as key_type,
        ):
            load_kerberos_ccache("/tmp/test.ccache", target_host="dc01.lab.local")

        ticket_type.return_value.from_asn1.assert_called_once_with(b"service")
        key_type.assert_called_once_with(18, b"service")

    def test_s4u_cache_is_copied_and_hostname_is_normalized(self):
        server = SimpleNamespace(components=[
            {"data": b"TERMSRV"},
            {"data": b"DC01"},
        ])
        cache = SimpleNamespace(credentials=[{"server": server}])
        cache.saveFile = lambda path: Path(path).write_bytes(b"cache")
        ticket = SimpleNamespace(
            service_principal=SimpleNamespace(components=["TERMSRV", "DC01"]),
        )

        with tempfile.TemporaryDirectory() as root:
            prepared_dir = Path(root) / "private"
            prepared_dir.mkdir()
            with (
                patch("pwnrm.core.utils.CCache.loadFile", return_value=cache),
                patch("pwnrm.core.utils.tempfile.mkdtemp", return_value=str(prepared_dir)),
                patch("pwnrm.core.utils.atexit.register"),
            ):
                prepared = prepare_kerberos_ccache("FILE:/tmp/source.ccache", ticket)

            prepared_path = Path(prepared.removeprefix("FILE:"))
            self.assertEqual(server.components[1]["data"], b"dc01")
            self.assertEqual(prepared_path.read_bytes(), b"cache")
            self.assertEqual(os.stat(prepared_path).st_mode & 0o777, 0o600)
            self.assertEqual(os.stat(prepared_path.parent).st_mode & 0o777, 0o700)

    def test_tgt_cache_is_used_without_copying(self):
        ticket = SimpleNamespace(
            service_principal=SimpleNamespace(
                components=["krbtgt", "LAB.LOCAL"],
            ),
        )
        with patch("pwnrm.core.utils.CCache.loadFile") as load_cache:
            prepared = prepare_kerberos_ccache("/tmp/tgt.ccache", ticket)

        self.assertEqual(prepared, "FILE:/tmp/tgt.ccache")
        load_cache.assert_not_called()


if __name__ == "__main__":
    unittest.main()
