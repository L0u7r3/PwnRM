"""
core.session_mgr — Multi-Session Manager & Jump Graph Routing
Coordinates concurrent PSRP runspaces, switching, and serialized persistence.
"""

import os
import json
import time
import stat
import logging
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List
from cryptography.fernet import Fernet

# In-memory ephemeral key — session metadata encrypted on disk and unreadable post-process
_SESSION_KEY = Fernet(Fernet.generate_key())


class SessionNode:
    """Represents a single managed PwnRM session."""
    def __init__(self, session_id: int, name: str, runspace, transport, target_info: dict):
        self.session_id = session_id
        self.name = name
        self.runspace = runspace
        self.transport = transport
        self.target_info = target_info
        self.created_at = datetime.now()
        self.last_active = datetime.now()
        self.is_alive = True
        self.notes = ""

    @property
    def host(self) -> str:
        return self.target_info.get("host", "unknown")

    @property
    def user(self) -> str:
        return self.target_info.get("user", "unknown")

    def to_dict(self) -> dict:
        return {
            "id": self.session_id,
            "name": self.name,
            "host": self.host,
            "user": self.user,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "is_alive": self.is_alive,
            "notes": self.notes,
        }


class SessionManager:
    """
    Coordinates multiple active Runspace sessions across multiple endpoints.
    Provides session switching, background execution, and fan-out capability.
    """
    def __init__(self, base_dir: Optional[Path] = None):
        self.sessions: Dict[int, SessionNode] = {}
        self.current_session_id: Optional[int] = None
        self._next_id = 0
        self.base_dir = base_dir or Path(os.environ.get("PWNRM_DIR", str(Path.home() / ".pwnrm")))
        self.sessions_dir = self.base_dir / "sessions"
        self._ensure_secure_dir()

    def _ensure_secure_dir(self):
        if self.sessions_dir.is_symlink():
            raise OSError(f"refusing to use symlinked session directory: {self.sessions_dir}")
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        if self.sessions_dir.is_symlink() or not self.sessions_dir.is_dir():
            raise OSError(f"session path is not a real directory: {self.sessions_dir}")
        try:
            os.chmod(self.sessions_dir, stat.S_IRWXU)
            import platform
            if platform.system() == "Windows":
                import subprocess
                user = os.environ.get("USERNAME")
                if user:
                    subprocess.run(
                        ["icacls", str(self.sessions_dir), "/inheritance:r", "/grant", f"{user}:(OI)(CI)F"],
                        capture_output=True,
                        creationflags=0x08000000
                    )
        except OSError:
            pass

    def register_session(self, runspace, transport, target_info: dict, name: str = "") -> SessionNode:
        sid = self._next_id
        self._next_id += 1
        sess_name = name or f"session-{sid}_{target_info.get('host', 'unknown')}"
        node = SessionNode(sid, sess_name, runspace, transport, target_info)
        self.sessions[sid] = node
        if self.current_session_id is None:
            self.current_session_id = sid
        return node

    def get_current(self) -> Optional[SessionNode]:
        if self.current_session_id is not None:
            return self.sessions.get(self.current_session_id)
        return None

    def switch_session(self, session_id: int) -> bool:
        if session_id in self.sessions:
            self.current_session_id = session_id
            node = self.sessions[session_id]
            node.last_active = datetime.now()
            return True
        return False

    def rename_session(self, session_id: int, new_name: str) -> bool:
        if session_id in self.sessions:
            self.sessions[session_id].name = new_name
            return True
        return False

    def close_session(self, session_id: int) -> bool:
        if session_id in self.sessions:
            node = self.sessions.pop(session_id)
            node.is_alive = False
            try:
                if hasattr(node.runspace, "__exit__"):
                    node.runspace.__exit__(None, None, None)
            except Exception as e:
                logging.debug("Error closing runspace %s: %s", session_id, e)
            if self.current_session_id == session_id:
                self.current_session_id = next(iter(self.sessions.keys())) if self.sessions else None
            return True
        return False

    def list_sessions(self) -> List[dict]:
        res = []
        for sid, node in self.sessions.items():
            d = node.to_dict()
            d["is_current"] = (sid == self.current_session_id)
            res.append(d)
        return res

    def fan_out_exec(self, cmd: str) -> Dict[int, str]:
        """Execute a command across all active sessions with [S:X | Host] output labeling."""
        active = [(sid, node) for sid, node in list(self.sessions.items()) if node.is_alive]

        def execute(sid, node):
            prefix = f"[S:{sid} | {node.host}]"
            try:
                out = []
                for o in node.runspace.run_command(cmd):
                    if "stdout" in o:
                        for line in o["stdout"].splitlines():
                            out.append(f"{prefix} {line}")
                    if "error" in o:
                        out.append(f"{prefix} [ERROR] {o['error']}")
                node.last_active = datetime.now()
                return sid, "\n".join(out)
            except Exception as e:
                return sid, f"{prefix} [ERROR] {e}"

        if not active:
            return {}
        completed = {}
        with ThreadPoolExecutor(max_workers=min(32, len(active)), thread_name_prefix="pwnrm-session") as pool:
            futures = [pool.submit(execute, sid, node) for sid, node in active]
            for future in as_completed(futures):
                sid, output = future.result()
                completed[sid] = output
        return {sid: completed[sid] for sid, _ in active}

    @staticmethod
    def _validate_state_filename(filename: str) -> str:
        if (
            not filename
            or filename in {".", ".."}
            or "/" in filename
            or "\\" in filename
            or "\x00" in filename
        ):
            raise ValueError("session state filename must be a simple file name")
        return filename

    def save_state(self, filename: str = "sessions.json") -> str:
        """Serialize and encrypt session metadata securely to disk using in-memory key."""
        filename = self._validate_state_filename(filename)
        target_file = self.sessions_dir / filename
        data = {
            "saved_at": datetime.now().isoformat(),
            "active_session": self.current_session_id,
            "sessions": [s.to_dict() for s in self.sessions.values()]
        }
        raw_bytes = json.dumps(data, indent=2).encode("utf-8")
        encrypted_bytes = _SESSION_KEY.encrypt(raw_bytes)
        if target_file.is_symlink():
            raise OSError(f"refusing to replace symlinked session state: {target_file}")
        tmp_file = self.sessions_dir / f".{filename}.{secrets.token_hex(8)}.tmp"
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(tmp_file), flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(encrypted_bytes)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_file, target_file)
            os.chmod(target_file, 0o600)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                tmp_file.unlink(missing_ok=True)
            except OSError:
                pass
        return str(target_file)

    def load_state(self, filename: str = "sessions.json") -> dict:
        """Decrypts and loads session metadata from disk using the in-memory key."""
        filename = self._validate_state_filename(filename)
        target_file = self.sessions_dir / filename
        if not target_file.exists():
            return {}
        if target_file.is_symlink():
            raise OSError(f"refusing to read symlinked session state: {target_file}")
        encrypted_bytes = target_file.read_bytes()
        decrypted_bytes = _SESSION_KEY.decrypt(encrypted_bytes)
        return json.loads(decrypted_bytes.decode("utf-8"))
