"""Secure Ligolo-ng agent acquisition and connection-profile storage."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import stat
import zipfile
from pathlib import Path
from typing import Optional

import requests


_REPOSITORY = "nicocha30/ligolo-ng"
_API_ROOT = f"https://api.github.com/repos/{_REPOSITORY}"
_MAX_ARCHIVE = 64 * 1024 * 1024
_MAX_AGENT = 128 * 1024 * 1024
_PROFILE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_FINGERPRINT = re.compile(r"^[A-Fa-f0-9]{64}$")


class LigoloAssetManager:
    def __init__(self, base_dir: Path, session: Optional[requests.Session] = None):
        self.base_dir = Path(base_dir)
        self.tools_dir = self.base_dir / "tools" / "ligolo-ng"
        self.profiles_file = self.tools_dir / "profiles.json"
        self.session = session or requests.Session()
        self._ensure_secure_dir(self.tools_dir)

    @staticmethod
    def _ensure_secure_dir(path: Path) -> None:
        if path.is_symlink():
            raise OSError(f"refusing to use symlinked Ligolo directory: {path}")
        path.mkdir(parents=True, exist_ok=True)
        if path.is_symlink() or not path.is_dir():
            raise OSError(f"Ligolo path is not a real directory: {path}")
        os.chmod(path, stat.S_IRWXU)

    def _release(self, version: str = "") -> dict:
        endpoint = f"{_API_ROOT}/releases/latest" if not version else f"{_API_ROOT}/releases/tags/v{version.lstrip('v')}"
        response = self.session.get(
            endpoint,
            timeout=20,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "PwnRM/2.1"},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or not payload.get("tag_name"):
            raise RuntimeError("GitHub returned an invalid Ligolo-ng release document")
        return payload

    def _download(self, url: str) -> bytes:
        response = self.session.get(url, timeout=60, stream=True, headers={"User-Agent": "PwnRM/2.1"})
        response.raise_for_status()
        data = bytearray()
        for chunk in response.iter_content(1024 * 1024):
            if not chunk:
                continue
            data.extend(chunk)
            if len(data) > _MAX_ARCHIVE:
                raise RuntimeError("Ligolo-ng release asset exceeds 64 MiB")
        return bytes(data)

    @staticmethod
    def _asset(release: dict, name: str) -> dict:
        for asset in release.get("assets", []):
            if asset.get("name") == name and asset.get("browser_download_url"):
                return asset
        raise RuntimeError(f"Ligolo-ng release asset not found: {name}")

    def fetch(self, *, version: str = "", architecture: str = "amd64") -> dict:
        if architecture not in {"amd64", "386", "arm64"}:
            raise ValueError("Ligolo architecture must be amd64, 386, or arm64")
        release = self._release(version)
        resolved = str(release["tag_name"]).lstrip("v")
        archive_name = f"ligolo-ng_agent_{resolved}_windows_{architecture}.zip"
        checksum_name = f"ligolo-ng_{resolved}_checksums.txt"
        archive = self._download(self._asset(release, archive_name)["browser_download_url"])
        checksums = self._download(self._asset(release, checksum_name)["browser_download_url"]).decode("utf-8", "replace")
        expected = ""
        for line in checksums.splitlines():
            fields = line.strip().split()
            if len(fields) >= 2 and fields[-1].lstrip("*") == archive_name:
                expected = fields[0].lower()
                break
        digest = hashlib.sha256(archive).hexdigest()
        if not expected or not secrets.compare_digest(digest, expected):
            raise RuntimeError("Ligolo-ng archive checksum verification failed")

        with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
            members = [item for item in bundle.infolist() if Path(item.filename).name.lower() == "agent.exe"]
            if len(members) != 1 or members[0].is_dir() or members[0].file_size > _MAX_AGENT:
                raise RuntimeError("Ligolo-ng archive does not contain one safe agent.exe")
            agent = bundle.read(members[0])
        if not agent.startswith(b"MZ"):
            raise RuntimeError("downloaded Ligolo-ng agent is not a Windows PE")

        destination_dir = self.tools_dir / resolved / architecture
        self._ensure_secure_dir(destination_dir)
        destination = destination_dir / "agent.exe"
        if destination.is_symlink():
            raise OSError(f"refusing to replace symlinked Ligolo agent: {destination}")
        temporary = destination_dir / f".agent.{secrets.token_hex(8)}.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(temporary), flags, 0o700)
        try:
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(agent)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            os.chmod(destination, 0o700)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        return {"path": str(destination), "version": resolved, "architecture": architecture, "sha256": hashlib.sha256(agent).hexdigest()}

    def latest_installed(self, architecture: str) -> str:
        candidates = sorted(
            (
                path for path in self.tools_dir.glob(f"*/{architecture}/agent.exe")
                if path.is_file() and not path.is_symlink()
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        return str(candidates[0]) if candidates else ""

    def list_installed(self) -> list[dict[str, str]]:
        result = []
        for path in sorted(self.tools_dir.glob("*/*/agent.exe")):
            if path.is_file() and not path.is_symlink():
                result.append({
                    "version": path.parent.parent.name,
                    "architecture": path.parent.name,
                    "path": str(path),
                })
        return result

    def _read_profiles(self) -> dict:
        if self.profiles_file.is_symlink():
            raise OSError(f"refusing to read symlinked Ligolo profiles: {self.profiles_file}")
        if not self.profiles_file.exists():
            return {}
        try:
            with self.profiles_file.open("r", encoding="utf-8") as handle:
                value = json.load(handle)
        except (OSError, json.JSONDecodeError, TypeError):
            return {}
        return value if isinstance(value, dict) else {}

    def _write_profiles(self, profiles: dict) -> None:
        if self.profiles_file.is_symlink():
            raise OSError(f"refusing to replace symlinked Ligolo profiles: {self.profiles_file}")
        temporary = self.tools_dir / f".profiles.{secrets.token_hex(8)}.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(temporary), flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                json.dump(profiles, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.profiles_file)
            os.chmod(self.profiles_file, 0o600)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    def save_profile(
        self,
        name: str,
        connect: str,
        *,
        ignore_cert: bool = False,
        fingerprint: str = "",
        retry: bool = True,
    ) -> dict:
        if not _PROFILE_NAME.fullmatch(name):
            raise ValueError("profile name must contain only letters, digits, dot, dash, or underscore")
        if not connect or any(char in connect for char in "\r\n\x00"):
            raise ValueError("profile connect endpoint is invalid")
        if ignore_cert and fingerprint:
            raise ValueError("choose either ignore-cert or a certificate fingerprint")
        fingerprint = fingerprint.replace(":", "")
        if fingerprint and not _FINGERPRINT.fullmatch(fingerprint):
            raise ValueError("certificate fingerprint must contain 64 hexadecimal characters")
        profiles = self._read_profiles()
        profiles[name] = {
            "connect": connect,
            "ignore_cert": bool(ignore_cert),
            "fingerprint": fingerprint.lower(),
            "retry": bool(retry),
        }
        self._write_profiles(profiles)
        return profiles[name]

    def get_profile(self, name: str) -> dict:
        profiles = self._read_profiles()
        if name not in profiles:
            raise KeyError(f"unknown Ligolo profile: {name}")
        return dict(profiles[name])

    def list_profiles(self) -> dict:
        return self._read_profiles()

    def delete_profile(self, name: str) -> None:
        profiles = self._read_profiles()
        if name not in profiles:
            raise KeyError(f"unknown Ligolo profile: {name}")
        del profiles[name]
        self._write_profiles(profiles)
