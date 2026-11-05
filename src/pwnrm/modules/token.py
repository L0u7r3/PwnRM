"""Windows process-token and privilege reconnaissance."""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class TokenModule(BaseModule):
    name = "token"
    description = "Windows process Token inventory and privilege exposure audit"
    author = "uziii2208"
    options = {
        "--list": {"desc": "List all processes with process tokens and user accounts"},
        "--privs": {"desc": "Audit current process privileges and associated security impact"},
    }

    def run(self, shell, args: List[str]) -> Any:
        valid = set(self.options)
        unknown = [arg for arg in args if arg not in valid]
        if unknown:
            if "--elevate" in unknown:
                shell.write_warning("  [-] --elevate is not implemented: token reconnaissance never claims or changes identity.")
            else:
                shell.write_warning(f"  [-] Unknown token option(s): {', '.join(unknown)}")
            return {"status": "error", "error": "invalid or unsupported options"}
        selected = set(args) if args else {"--list", "--privs"}
        shell.write_info(c(M + BLD, "  [*] PwnRM Token Engine — auditing process identities and current privileges..."))

        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
$doPrivs = __DO_PRIVS__
$doList = __DO_LIST__
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Windows Token & Privilege Audit" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. Audit Current Privileges & Highlight Exploitable Rights
if ($doPrivs) {
Write-Host "[1. Current Process Privileges & Exposure Triage]" -ForegroundColor Yellow
$privs = whoami /priv 2>$null
$privMap = @{
    "SeImpersonatePrivilege"          = "CRITICAL: Impersonate client tokens (SYSTEM escalation via Named Pipe / Potato)"
    "SeAssignPrimaryTokenPrivilege"  = "CRITICAL: Assign primary token to child processes (SYSTEM escalation)"
    "SeDebugPrivilege"                = "HIGH: Memory access to any process (LSASS / token duplication)"
    "SeBackupPrivilege"               = "HIGH: Read arbitrary files (SAM, SYSTEM, NTDS.dit, private keys)"
    "SeRestorePrivilege"              = "HIGH: Write arbitrary files (system binary / DLL hijacking)"
    "SeTakeOwnershipPrivilege"        = "HIGH: Take ownership of any securable object"
    "SeTcbPrivilege"                  = "CRITICAL: Act as part of the operating system"
    "SeLoadDriverPrivilege"           = "HIGH: Load kernel mode drivers"
}

$foundCount = 0
foreach ($p in $privMap.Keys) {
    if ($privs -match $p) {
        $foundCount++
        $state = if ($privs -match "$p\s+Enabled") { "Enabled" } else { "Disabled (Available)" }
        Write-Host "  [!] $p [$state]" -ForegroundColor Red
        Write-Host "      → $($privMap[$p])" -ForegroundColor Yellow
    }
}

if ($foundCount -eq 0) {
    Write-Host "  [-] Standard unprivileged token (no high-impact privileges present)." -ForegroundColor Gray
}
}

# 2. Process & Token Enumeration (Find High-Value Process Targets)
if ($doList) {
Write-Host "`n[2. High-Value Running Process & Token Inventory]" -ForegroundColor Yellow
$procs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
if (-not $procs) {
    $procs = Get-WmiObject Win32_Process | Select-Object ProcessId, Name, @{N='UserName';E={$_.GetOwner().User}}
}

$systemProcs = 0
$adminProcs = 0
foreach ($pr in $procs | Select-Object -First 30) {
    $u = if ($pr.UserName) { $pr.UserName } else { "N/A" }
    $pname = $pr.ProcessName
    if (-not $pname) { $pname = $pr.Name }
    $pid_ = if ($pr.Id) { $pr.Id } else { $pr.ProcessId }

    if ($u -match "SYSTEM|Administrator|svc") {
        Write-Host "  [*] PID: $($pid_.ToString().PadRight(6)) | Process: $($pname.PadRight(25)) | User: $u" -ForegroundColor White
        if ($u -match "SYSTEM") { $systemProcs++ }
        if ($u -match "Administrator") { $adminProcs++ }
    }
}

Write-Host "`n[Token Landscape Summary]" -ForegroundColor Cyan
Write-Host "  SYSTEM Processes Observed        : $systemProcs" -ForegroundColor $(if ($systemProcs -gt 0) { "White" } else { "DarkGray" })
Write-Host "  Administrator Processes Observed : $adminProcs" -ForegroundColor $(if ($adminProcs -gt 0) { "White" } else { "DarkGray" })
}

Write-Host "`n  [*] Token audit complete." -ForegroundColor Cyan
"""
        ps = ps.replace("__DO_PRIVS__", "$true" if "--privs" in selected else "$false")
        ps = ps.replace("__DO_LIST__", "$true" if "--list" in selected else "$false")
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        if shell.run_with_interrupt(cmd, shell.write_line):
            return {"status": "interrupted"}
        return {"status": "completed", "selected": sorted(selected)}
