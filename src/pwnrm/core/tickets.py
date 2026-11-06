"""Read-only Kerberos ccache inventory and explicit cache renewal helpers."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from impacket.krb5.ccache import CCache
from impacket.krb5.constants import EncryptionTypes


def _principal(value: Any) -> str:
    try:
        rendered = value.prettyPrint()
        return rendered.decode(errors="replace") if isinstance(rendered, bytes) else str(rendered)
    except (AttributeError, TypeError, ValueError):
        components = []
        for component in getattr(value, "components", []):
            data = component.get("data", b"")
            components.append(data.decode(errors="replace") if isinstance(data, bytes) else str(data))
        realm = getattr(value, "realm", {}).get("data", b"")
        realm_text = realm.decode(errors="replace") if isinstance(realm, bytes) else str(realm)
        return "/".join(components) + (f"@{realm_text}" if realm_text else "")


def _field(value: Any, name: str, default: Any = None) -> Any:
    try:
        return value[name]
    except (KeyError, TypeError, AttributeError):
        if isinstance(value, dict):
            return value.get(name, default)
        return default


def _timestamp(value: Any) -> str:
    try:
        seconds = int(value or 0)
    except (TypeError, ValueError):
        seconds = 0
    if not seconds:
        return "-"
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


def _enctype(value: Any) -> str:
    try:
        parsed = int(value)
        return EncryptionTypes(parsed).name
    except (TypeError, ValueError):
        return str(value)


@dataclass(frozen=True)
class TicketEntry:
    index: int
    client: str
    server: str
    enctype: str
    flags: str
    auth_time: str
    start_time: str
    end_time: str
    renew_till: str

    @property
    def is_tgt(self) -> bool:
        return self.server.lower().startswith("krbtgt/")


@dataclass(frozen=True)
class CacheInfo:
    path: str
    principal: str
    tickets: tuple[TicketEntry, ...]

    @property
    def has_tgt(self) -> bool:
        return any(ticket.is_tgt for ticket in self.tickets)


class TicketManager:
    @staticmethod
    def normalize_path(path: str = "") -> Path:
        raw = path or os.environ.get("KRB5CCNAME", "")
        if raw.startswith("FILE:"):
            raw = raw[5:]
        candidate = Path(raw).expanduser()
        if not raw or not candidate.is_file() or candidate.is_symlink():
            raise FileNotFoundError(f"ccache not found or unsafe: {raw!r}")
        return candidate.resolve()

    def inspect(self, path: str = "") -> CacheInfo:
        cache_path = self.normalize_path(path)
        cache = CCache.loadFile(str(cache_path))
        entries = []
        for index, credential in enumerate(cache.credentials):
            times = _field(credential, "time", {})
            key = _field(credential, "key", {})
            flags = _field(credential, "tktflags", 0)
            try:
                flags_text = f"0x{int(flags):08x}"
            except (TypeError, ValueError):
                flags_text = str(flags)
            entries.append(TicketEntry(
                index=index,
                client=_principal(_field(credential, "client")),
                server=_principal(_field(credential, "server")),
                enctype=_enctype(_field(key, "keytype", "?")),
                flags=flags_text,
                auth_time=_timestamp(_field(times, "authtime", 0)),
                start_time=_timestamp(_field(times, "starttime", 0)),
                end_time=_timestamp(_field(times, "endtime", 0)),
                renew_till=_timestamp(_field(times, "renew_till", 0)),
            ))
        return CacheInfo(
            path=str(cache_path),
            principal=_principal(cache.principal),
            tickets=tuple(entries),
        )

    def renew(self, path: str = "") -> CacheInfo:
        cache_path = self.normalize_path(path)
        current = self.inspect(str(cache_path))
        if not current.has_tgt:
            raise ValueError("the selected ccache has no TGT and cannot be renewed")
        kinit = shutil.which("kinit")
        if not kinit:
            raise RuntimeError("kinit is not installed")
        completed = subprocess.run(
            [kinit, "-R", "-c", f"FILE:{cache_path}"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if completed.returncode:
            detail = (completed.stderr or completed.stdout).strip() or "unknown kinit error"
            raise RuntimeError(f"ticket renewal failed: {detail}")
        return self.inspect(str(cache_path))
