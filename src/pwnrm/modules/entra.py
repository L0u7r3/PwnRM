"""Hybrid Entra ID join-state and locally accessible cache inventory."""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class EntraModule(BaseModule):
    name = "entra"
    description = "Hybrid Entra ID join-state and accessible cloud-cache inventory"
    author = "uziii2208"
    options = {
        "full": {"desc": "Run full dsregcmd join status and WAM token probe"},
    }

    def run(self, shell, args: List[str]) -> Any:
        normalized = ["full" if arg.lower() in {"-s", "--full"} else arg.lower() for arg in args]
        unknown = [arg for arg in normalized if arg != "full"]
        if unknown:
            shell.write_warning(f"  [-] Unknown Entra option(s): {', '.join(unknown)}")
            return {"status": "error", "error": "invalid options"}
        full_scan = "full" in normalized
        full_scan_ps = "$true" if full_scan else "$false"
        shell.write_info(c(M + BLD, "  [*] PwnRM Entra Suite — running Azure AD / Hybrid Join reconnaissance..."))

        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
$fullScan = __FULL_SCAN__
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Hybrid Entra ID / Azure AD Artifact Recon" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. Device Join Status (AzureADJoined / DomainJoined)
Write-Host "[1. Device Join & PRT Status]" -ForegroundColor Yellow
$dsreg = dsregcmd /status 2>$null
if ($dsreg) {
    $dsreg | Where-Object { $_ -match "AzureAdJoined|DomainJoined|EnterpriseJoined|TenantName|TenantId|UserEmail|AzureAdPrt" } | ForEach-Object {
        Write-Host "  $_" -ForegroundColor White
    }
} else {
    Write-Host "  [-] dsregcmd not available or returned no data." -ForegroundColor Gray
}

if ($fullScan) {{
    # 2. Token Broker / WAM cache presence across locally accessible profiles.
    Write-Host "`n[2. Web Account Manager (WAM) & Cloud Token Stores]" -ForegroundColor Yellow
    $profiles = @(Get-ChildItem -LiteralPath "$env:SystemDrive\\Users" -Directory -Force | Select-Object -ExpandProperty FullName)
    if ($env:USERPROFILE -and $env:USERPROFILE -notin $profiles) {{ $profiles += $env:USERPROFILE }}
    $artifactCount = 0
    foreach ($profile in $profiles) {{
        $paths = @(
            "$profile\\AppData\\Local\\Packages\\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy",
            "$profile\\.azure\\accessTokens.json",
            "$profile\\.azure\\msal_token_cache.bin",
            "$profile\\.Azure\\AzureRmContext.json"
        )
        foreach ($path in $paths) {{
            if (Test-Path -LiteralPath $path) {{
                $artifactCount++
                Write-Host "  [!] Cloud authentication artifact found: $path" -ForegroundColor Red
            }}
        }}
    }}
    if ($artifactCount -eq 0) {{
        Write-Host "  [-] No accessible WAM, Azure CLI, or Azure PowerShell cache was found." -ForegroundColor Gray
    }}
}} else {{
    Write-Host "`n  [*] Join-state scan complete. Use 'full' for the full WAM/cloud-cache probe." -ForegroundColor Gray
}}

Write-Host "`n  [*] Entra reconnaissance complete." -ForegroundColor Cyan
"""
        ps = ps.replace("__FULL_SCAN__", full_scan_ps).replace("{{", "{").replace("}}", "}")
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        if shell.run_with_interrupt(cmd, shell.write_line):
            return {"status": "interrupted"}
        return {"status": "completed", "full_scan": full_scan}
