"""Tests for ephemeral dump parsing and buffer cleanup helpers."""

import unittest
from enum import Enum
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from pwnrm.core.credential_dump import (
    _stringify_secret,
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

    @patch("pwnrm.core.credential_dump.LSASecrets")
    @patch("pwnrm.core.credential_dump.SAMHashes")
    @patch("pwnrm.core.credential_dump.LocalOperations")
    def test_sam_and_lsa_callbacks_are_returned(self, local_cls, sam_cls, lsa_cls):
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
        self.assertEqual(records, ["local:500:lm:nt:::", "[LSA_HASHED] cached", "[LSA] secret"])

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
