"""
core.loot — Automated Structured Loot Pipeline
Manages credentials, tickets, certificates, and extracted artifacts with permission hardening and JSON manifests.
"""

import os
import json
import stat
import time
import hashlib
import secrets
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any


class LootManager:
    """
    Structured loot collection and storage engine with strict permission hardening.
    Organizes findings per target host/domain and maintains an operational MANIFEST.json.
    """
    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(os.environ.get("PWNRM_DIR", str(Path.home() / ".pwnrm")))
        self.loot_root = self.base_dir / "loot"
        self._ensure_secure_dir(self.loot_root)
        self.manifest_file = self.loot_root / "MANIFEST.json"
        self._lock = threading.RLock()

    def _ensure_secure_dir(self, d: Path):
        if d.is_symlink():
            raise OSError(f"refusing to use symlinked loot directory: {d}")
        d.mkdir(parents=True, exist_ok=True)
        if d.is_symlink() or not d.is_dir():
            raise OSError(f"loot path is not a real directory: {d}")
        try:
            os.chmod(d, stat.S_IRWXU)
            import platform
            if platform.system() == "Windows":
                import subprocess
                user = os.environ.get("USERNAME")
                if user:
                    subprocess.run(
                        ["icacls", str(d), "/inheritance:r", "/grant", f"{user}:(OI)(CI)F"],
                        capture_output=True,
                        creationflags=0x08000000
                    )
        except OSError:
            pass

    @staticmethod
    def _read_json(path: Path, default):
        if path.is_symlink():
            raise OSError(f"refusing to read symlinked loot file: {path}")
        if not path.exists():
            return default
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    @staticmethod
    def _atomic_json_write(path: Path, value) -> None:
        """Write JSON with mode 0600 without following an attacker-made symlink."""
        if path.is_symlink():
            raise OSError(f"refusing to replace symlinked loot file: {path}")
        tmp = path.parent / f".{path.name}.{secrets.token_hex(8)}.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(tmp), flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                json.dump(value, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
            os.chmod(path, 0o600)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _update_manifest(self, entry: dict):
        manifest_data = {"artifacts": []}
        with self._lock:
            try:
                manifest_data = self._read_json(self.manifest_file, manifest_data)
            except (OSError, json.JSONDecodeError, TypeError):
                if self.manifest_file.is_symlink():
                    raise
                manifest_data = {"artifacts": []}
            if not isinstance(manifest_data, dict):
                manifest_data = {"artifacts": []}
            artifacts = manifest_data.setdefault("artifacts", [])
            if not isinstance(artifacts, list):
                manifest_data["artifacts"] = artifacts = []
            artifacts.append(entry)
            self._atomic_json_write(self.manifest_file, manifest_data)

    def get_target_dir(self, target: str) -> Path:
        sanitized = "".join(c for c in target if c.isalnum() or c in "._-").strip() or "general"
        tdir = self.loot_root / sanitized
        self._ensure_secure_dir(tdir)
        for sub in ("tickets", "certs", "dpapi", "bloodhound", "dumps"):
            self._ensure_secure_dir(tdir / sub)
        return tdir

    def store_credential(self, target: str, cred_type: str, account: str, secret: str, source: str = "triage") -> dict:
        tdir = self.get_target_dir(target)
        creds_file = tdir / "credentials.json"
        with self._lock:
            try:
                creds_list = self._read_json(creds_file, [])
            except (OSError, json.JSONDecodeError, TypeError):
                if creds_file.is_symlink():
                    raise
                creds_list = []
            if not isinstance(creds_list, list):
                creds_list = []

            entry = {
                "type": cred_type,
                "account": account,
                "secret": secret,
                "source": source,
                "timestamp": datetime.now().isoformat()
            }
            creds_list.append(entry)
            self._atomic_json_write(creds_file, creds_list)

        self._update_manifest({
            "filename": "credentials.json",
            "type": f"credential_{cred_type}",
            "category": "credentials",
            "source_command": source,
            "timestamp": entry["timestamp"],
            "sha256": hashlib.sha256(secret.encode()).hexdigest(),
            "target": target,
            "account": account
        })
        return entry

    def store_artifact(self, target: str, category: str, filename: str, data: bytes, source_command: str = "loot") -> str:
        """Stores binary or text artifact (cert, ticket, dump) under the target category and updates manifest."""
        tdir = self.get_target_dir(target)
        if (
            not category
            or category in {".", ".."}
            or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for c in category)
        ):
            raise ValueError("artifact category must be a simple directory name")
        cat_dir = tdir / category
        self._ensure_secure_dir(cat_dir)
        safe_name = "".join(c for c in filename if c.isalnum() or c in "._-").strip() or "artifact.bin"
        if safe_name in {".", ".."}:
            safe_name = "artifact.bin"
        dst = cat_dir / safe_name
        if dst.is_symlink():
            raise OSError(f"refusing to replace symlinked artifact: {dst}")
        flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(dst), flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(dst, 0o600)
        finally:
            if fd >= 0:
                os.close(fd)

        file_sha256 = hashlib.sha256(data).hexdigest()
        self._update_manifest({
            "filename": safe_name,
            "type": category,
            "category": category,
            "source_command": source_command,
            "timestamp": datetime.now().isoformat(),
            "sha256": file_sha256,
            "target": target,
            "path": str(dst)
        })
        return str(dst)

    def list_target_loot(self, target: str) -> dict:
        tdir = self.get_target_dir(target)
        creds = []
        creds_file = tdir / "credentials.json"
        if creds_file.exists():
            try:
                creds = self._read_json(creds_file, [])
            except (OSError, json.JSONDecodeError, TypeError):
                creds = []
        if not isinstance(creds, list):
            creds = []
        artifacts = {}
        for sub_dir in sorted(tdir.iterdir(), key=lambda path: path.name):
            if not sub_dir.is_dir() or sub_dir.is_symlink():
                continue
            artifacts[sub_dir.name] = sorted(
                f.name for f in sub_dir.iterdir() if f.is_file() and not f.is_symlink()
            )
        return {"target": target, "credentials": creds, "artifacts": artifacts}

    def summary(self) -> dict:
        summary_data = {}
        for item in self.loot_root.iterdir():
            if item.is_dir() and not item.is_symlink():
                summary_data[item.name] = self.list_target_loot(item.name)
        return summary_data
