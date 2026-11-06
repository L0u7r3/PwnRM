"""Persistent operator-side registry for PwnRM background and detached jobs."""

from __future__ import annotations

import json
import os
import secrets
import stat
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


_TERMINAL_STATES = {"completed", "failed", "stopped", "missing", "orphaned"}


@dataclass
class JobRecord:
    job_id: str
    target: str
    kind: str
    name: str
    mode: str
    remote_id: str = ""
    pid: Optional[int] = None
    status: str = "running"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    output_available: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def terminal(self) -> bool:
        return self.status in _TERMINAL_STATES

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "JobRecord":
        allowed = {item.name for item in cls.__dataclass_fields__.values()}
        return cls(**{key: val for key, val in value.items() if key in allowed})


class JobRegistry:
    """Track jobs and persist only non-secret operational metadata as mode 0600."""

    def __init__(self, base_dir: Path, target: str):
        self.base_dir = Path(base_dir)
        self.target = target.strip().lower() or "unknown"
        self.jobs_dir = self.base_dir / "jobs"
        self.state_file = self.jobs_dir / "registry.json"
        self._lock = threading.RLock()
        self._ensure_secure_dir()
        self._records = self._load()
        # A runspace-owned job cannot survive a new PwnRM process. Preserve the
        # record for operator visibility but never claim it is still running.
        changed = False
        for record in self._records.values():
            if record.mode == "runspace" and record.status == "running":
                record.status = "orphaned"
                record.updated_at = datetime.now(timezone.utc).isoformat()
                changed = True
        if changed:
            self._save()

    def _ensure_secure_dir(self) -> None:
        if self.jobs_dir.is_symlink():
            raise OSError(f"refusing to use symlinked jobs directory: {self.jobs_dir}")
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        if self.jobs_dir.is_symlink() or not self.jobs_dir.is_dir():
            raise OSError(f"jobs path is not a real directory: {self.jobs_dir}")
        os.chmod(self.jobs_dir, stat.S_IRWXU)

    def select_target(self, target: str) -> None:
        """Select which target's jobs are visible to the active shell session."""
        normalized = target.strip().lower()
        if not normalized:
            raise ValueError("job registry target cannot be empty")
        with self._lock:
            self.target = normalized

    def _load(self) -> dict[str, JobRecord]:
        if self.state_file.is_symlink():
            raise OSError(f"refusing to read symlinked jobs file: {self.state_file}")
        if not self.state_file.exists():
            return {}
        try:
            with self.state_file.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            return {}
        records: dict[str, JobRecord] = {}
        for item in payload.get("jobs", []) if isinstance(payload, dict) else []:
            try:
                record = JobRecord.from_dict(item)
            except (TypeError, ValueError):
                continue
            records[record.job_id] = record
        return records

    def _save(self) -> None:
        if self.state_file.is_symlink():
            raise OSError(f"refusing to replace symlinked jobs file: {self.state_file}")
        tmp = self.jobs_dir / f".registry.{secrets.token_hex(8)}.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(tmp), flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                json.dump(
                    {"jobs": [record.to_dict() for record in self._records.values()]},
                    handle,
                    indent=2,
                    sort_keys=True,
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.state_file)
            os.chmod(self.state_file, 0o600)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def register(
        self,
        *,
        kind: str,
        name: str,
        mode: str,
        remote_id: str = "",
        pid: Optional[int] = None,
        output_available: bool = False,
        metadata: Optional[dict[str, Any]] = None,
        job_id: str = "",
    ) -> JobRecord:
        if mode not in {"runspace", "process"}:
            raise ValueError("job mode must be runspace or process")
        with self._lock:
            local_id = job_id or secrets.token_hex(4)
            while local_id in self._records:
                local_id = secrets.token_hex(4)
            record = JobRecord(
                job_id=local_id,
                target=self.target,
                kind=kind,
                name=name,
                mode=mode,
                remote_id=remote_id,
                pid=pid,
                output_available=output_available,
                metadata=dict(metadata or {}),
            )
            self._records[local_id] = record
            self._save()
            return record

    def list(self, *, kind: str = "") -> list[JobRecord]:
        with self._lock:
            records = [
                record for record in self._records.values()
                if record.target == self.target and (not kind or record.kind == kind)
            ]
            return sorted(records, key=lambda item: item.created_at)

    def resolve(self, identifier: str, *, kind: str = "") -> JobRecord:
        needle = identifier.strip().lower()
        matches = [
            record for record in self.list(kind=kind)
            if record.job_id.lower().startswith(needle)
            or (record.remote_id and record.remote_id.lower().startswith(needle))
            or (record.pid is not None and str(record.pid) == needle)
        ]
        if not matches:
            raise KeyError(f"unknown job: {identifier}")
        if len(matches) > 1:
            raise KeyError(f"ambiguous job identifier: {identifier}")
        return matches[0]

    def update(self, record: JobRecord, **changes: Any) -> JobRecord:
        with self._lock:
            for key, value in changes.items():
                if not hasattr(record, key):
                    raise ValueError(f"unknown job field: {key}")
                setattr(record, key, value)
            record.updated_at = datetime.now(timezone.utc).isoformat()
            self._records[record.job_id] = record
            self._save()
            return record

    def remove(self, record: JobRecord) -> None:
        with self._lock:
            self._records.pop(record.job_id, None)
            self._save()

    def cleanup_terminal(self, *, kind: str = "") -> list[str]:
        with self._lock:
            removed = [
                record.job_id for record in self.list(kind=kind) if record.terminal
            ]
            for job_id in removed:
                self._records.pop(job_id, None)
            self._save()
            return removed
