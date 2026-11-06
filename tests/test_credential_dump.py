"""Tests for ephemeral dump parsing and buffer cleanup helpers."""

import unittest
import zipfile
from enum import Enum
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pwnrm.core.credential_dump import (
    _stringify_secret,
    dump_remote_registry,
    extract_zip_artifacts,
    parse_lsass_minidump,
    parse_registry_artifacts,
    zeroize,
)


class TestCredentialDump(unittest.TestCase):
    def test_numeric_callback_type_uses_impacket_enum_name(self):
        class SecretType(Enum):
            MACHINE_ACCOUNT = 3

        self.assertEqual(
            _stringify_secret(3, "secret", SecretType),
            "[MACHINE_ACCOUNT] secret",
        )

    def test_impacket_constant_container_uses_symbolic_name(self):
        class SecretType:
            LSA = 0
            LSA_KERBEROS = 3

        self.assertEqual(
            _stringify_secret(3, "secret", SecretType),
            "[LSA_KERBEROS] secret",
        )

    @patch("pwnrm.core.credential_dump.LSASecrets")
    @patch("pwnrm.core.credential_dump.SAMHashes")
    @patch("pwnrm.core.credential_dump.LocalOperations")
    def test_sam_mode_does_not_dump_lsa_secrets(self, local_cls, sam_cls, lsa_cls):
        local_cls.return_value.getBootKey.return_value = b"boot-key"

        def sam_factory(*args, **kwargs):
            callback = kwargs["perSecretCallback"]
            return SimpleNamespace(dump=lambda: callback("local:500:lm:nt:::"), finish=lambda: None)

        def lsa_factory(*args, **kwargs):
            callback = kwargs["perSecretCallback"]
            return SimpleNamespace(
                dumpCachedHashes=lambda: callback(SimpleNamespace(name="LSA_HASHED"), "cached"),
                dumpSecrets=lambda: callback(SimpleNamespace(name="LSA"), "secret"),
                finish=lambda: None,
            )

        sam_cls.side_effect = sam_factory
        lsa_cls.side_effect = lsa_factory
        records = parse_registry_artifacts(
            "sam",
            {
                "SYSTEM": bytearray(b"system"),
                "SAM": bytearray(b"sam"),
                "SECURITY": bytearray(b"security"),
            },
        )
        self.assertEqual(records, ["local:500:lm:nt:::"])
        lsa_cls.assert_not_called()

    @patch("pwnrm.core.credential_dump.LSASecrets")
    @patch("pwnrm.core.credential_dump.LocalOperations")
    def test_lsa_mode_returns_only_lsa_callbacks(self, local_cls, lsa_cls):
        local_cls.return_value.getBootKey.return_value = b"boot-key"

        def lsa_factory(*args, **kwargs):
            callback = kwargs["perSecretCallback"]
            return SimpleNamespace(
                dumpCachedHashes=lambda: callback(SimpleNamespace(name="LSA_HASHED"), "cached"),
                dumpSecrets=lambda: callback(SimpleNamespace(name="LSA"), "secret"),
                finish=lambda: None,
            )

        lsa_cls.side_effect = lsa_factory
        records = parse_registry_artifacts(
            "lsa",
            {"SYSTEM": bytearray(b"system"), "SECURITY": bytearray(b"security")},
        )
        self.assertEqual(records, ["[LSA_HASHED] cached", "[LSA] secret"])

    def test_zip_artifacts_extract_only_explicit_members(self):
        archive = BytesIO()
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
            handle.writestr("SYSTEM", b"system")
            handle.writestr("SAM", b"sam")
            handle.writestr("ignored.txt", b"ignored")
        extracted = extract_zip_artifacts(bytearray(archive.getvalue()), ["SYSTEM", "SAM"])
        self.assertEqual(extracted, {"SYSTEM": bytearray(b"system"), "SAM": bytearray(b"sam")})

    @patch("pwnrm.core.credential_dump.RemoteOperations")
    @patch("pwnrm.core.credential_dump.SAMHashes")
    def test_remote_registry_sam_uses_remote_file_without_local_staging(self, sam_cls, ops_cls):
        remote_file = MagicMock()
        remote_file.read.side_effect = [b"regf-hive", b""]
        ops = ops_cls.return_value
        registry_rpc = MagicMock()
        setattr(ops, "_RemoteOperations__rrp", registry_rpc)
        ops.getBootKey.return_value = b"boot-key"
        ops.saveSAM.return_value = remote_file
        cleanup_order = []
        registry_rpc.disconnect.side_effect = lambda: cleanup_order.append("disconnect")
        ops.finish.side_effect = lambda: cleanup_order.append("finish")

        def sam_factory(*args, **kwargs):
            callback = kwargs["perSecretCallback"]
            return SimpleNamespace(
                dump=lambda: callback("local:500:lm:nt:::"),
                finish=lambda: None,
            )

        sam_cls.side_effect = sam_factory
        records = dump_remote_registry(MagicMock(), "sam", do_kerberos=True)
        self.assertEqual(records, ["local:500:lm:nt:::"])
        ops.enableRegistry.assert_called_once()
        ops.saveSAM.assert_called_once()
        ops.finish.assert_called_once()
        self.assertIsNot(sam_cls.call_args.args[0], remote_file)
        remote_file.open.assert_called_once()
        remote_file.close.assert_called_once()
        self.assertTrue(sam_cls.call_args.kwargs["isRemote"])
        self.assertEqual(cleanup_order, ["disconnect", "finish"])
        self.assertIsNone(getattr(ops, "_RemoteOperations__rrp"))

    @patch("pwnrm.core.credential_dump.NTDSHashes")
    @patch("pwnrm.core.credential_dump.LocalOperations")
    def test_ntds_callback_is_returned(self, local_cls, ntds_cls):
        local_cls.return_value.getBootKey.return_value = b"boot-key"
        local_cls.return_value.checkNoLMHashPolicy.return_value = True
        ntds_cls.getLocalDomainSid.return_value = "S-1-5-21"

        def ntds_factory(*args, **kwargs):
            callback = kwargs["perSecretCallback"]
            return SimpleNamespace(
                dump=lambda: callback(SimpleNamespace(name="NTDS"), "DOMAIN\\user:hash"),
                finish=lambda: None,
            )

        ntds_cls.side_effect = ntds_factory
        records = parse_registry_artifacts(
            "ntds",
            {"SYSTEM": bytearray(b"system"), "ntds.dit": bytearray(b"ntds")},
        )
        self.assertEqual(records, ["[NTDS] DOMAIN\\user:hash"])

    def test_lsass_parser_uses_memory_bytes(self):
        parsed = MagicMock()
        parsed.to_grep.return_value = "header\r\ncredential\r\n"
        with patch("pypykatz.pypykatz.pypykatz.parse_minidump_bytes", return_value=parsed) as parser:
            data = bytearray(b"minidump")
            self.assertEqual(parse_lsass_minidump(data), ["header", "credential"])
            parser.assert_called_once_with(data)

    def test_zeroize_overwrites_every_buffer(self):
        first = bytearray(b"secret")
        second = bytearray(b"hash")
        zeroize([first, second])
        self.assertEqual(first, bytearray(len(first)))
        self.assertEqual(second, bytearray(len(second)))


if __name__ == "__main__":
    unittest.main()
