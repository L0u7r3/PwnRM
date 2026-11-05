"""
tests.test_loot — Unit tests for LootManager & MANIFEST.json tracking
"""

import json
import hashlib
import tempfile
import os
import unittest
from pathlib import Path
from pwnrm.core.loot import LootManager


class TestLootManager(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.loot = LootManager(base_dir=Path(self.temp_dir.name))

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_store_and_retrieve_credentials(self):
        target = "dc01.corp.local"
        entry = self.loot.store_credential(target, "NTLM", "CORP\\Administrator", "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0", "sam_dump")
        self.assertEqual(entry["account"], "CORP\\Administrator")

        loot_data = self.loot.list_target_loot(target)
        self.assertEqual(len(loot_data["credentials"]), 1)
        self.assertEqual(loot_data["credentials"][0]["secret"], "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0")

    def test_store_artifact_and_manifest(self):
        target = "srv01"
        data = b"PFXDATA123"
        saved = self.loot.store_artifact(target, "certs", "admin.pfx", data, source_command="!adcs")
        self.assertTrue(Path(saved).exists())
        summary = self.loot.summary()
        self.assertIn("srv01", summary)
        self.assertIn("admin.pfx", summary["srv01"]["artifacts"]["certs"])

        # Check MANIFEST.json
        manifest_path = self.loot.manifest_file
        self.assertTrue(manifest_path.exists())
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertTrue(len(manifest.get("artifacts", [])) >= 1)
        found = [a for a in manifest["artifacts"] if a.get("filename") == "admin.pfx"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(found[0]["source_command"], "!adcs")

    def test_custom_artifact_category_is_visible_in_summary(self):
        self.loot.store_artifact("srv01", "reports", "triage.txt", b"ok")
        self.assertEqual(
            self.loot.summary()["srv01"]["artifacts"]["reports"],
            ["triage.txt"],
        )

    def test_rejects_category_traversal(self):
        with self.assertRaises(ValueError):
            self.loot.store_artifact("srv01", "../../outside", "x.bin", b"x")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_refuses_symlinked_sensitive_files(self):
        outside = Path(self.temp_dir.name) / "outside.json"
        outside.write_text("unchanged", encoding="utf-8")
        target_dir = self.loot.get_target_dir("srv01")
        (target_dir / "credentials.json").symlink_to(outside)
        with self.assertRaises(OSError):
            self.loot.store_credential("srv01", "test", "user", "secret")
        self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")

        artifact = target_dir / "certs" / "admin.pfx"
        artifact.symlink_to(outside)
        with self.assertRaises(OSError):
            self.loot.store_artifact("srv01", "certs", "admin.pfx", b"new")
        self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks are unavailable")
    def test_refuses_symlinked_target_directory(self):
        outside = Path(self.temp_dir.name) / "outside"
        outside.mkdir()
        (self.loot.loot_root / "srv01").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            self.loot.store_artifact("srv01", "certs", "admin.pfx", b"new")


if __name__ == "__main__":
    unittest.main()
