"""Bounded Active Directory graph reconnaissance.

The historical command name is retained for compatibility. This module does
not pretend that a count-only summary is an importable BloodHound dataset.
"""

from typing import List, Any

from . import BaseModule
from ..shell.ui import c, M, BLD
from ..shell.commands import b64str


class BloodhoundModule(BaseModule):
    name = "bloodhound"
    description = "AD graph reconnaissance summary (users, computers, groups and local sessions)"
    author = "uziii2208"
    options = {
        "--collection": {"desc": "Methods: DCOnly, User, Computer, Group, Session, All (comma-separated)"},
    }

    _METHODS = {"dconly", "user", "computer", "group", "session", "all"}

    def run(self, shell, args: List[str]) -> Any:
        methods = {"dconly", "session"}
        if args:
            if len(args) != 2 or args[0].lower() not in {"-c", "--collection"}:
                shell.write_warning("  [-] Usage: !bloodhound [--collection DCOnly,User,Computer,Group,Session,All]")
                return {"status": "error", "error": "invalid syntax"}
            methods = {part.strip().lower() for part in args[1].split(",") if part.strip()}
            unknown = methods - self._METHODS
            if not methods or unknown:
                shell.write_warning(f"  [-] Unsupported collection method(s): {', '.join(sorted(unknown)) or '<empty>'}")
                return {"status": "error", "error": "invalid collection methods"}

        if "all" in methods:
            selected = {"user", "computer", "group", "session"}
        else:
            selected = methods - {"dconly"}
            if "dconly" in methods:
                selected.update({"user", "computer", "group"})

        shell.write_info(c(M + BLD, "  [*] PwnRM AD Graph Recon — starting selected LDAP/session summaries..."))

        ps = r'''
$ErrorActionPreference = 'SilentlyContinue'
$doUsers = __DO_USERS__
$doComputers = __DO_COMPUTERS__
$doGroups = __DO_GROUPS__
$doSessions = __DO_SESSIONS__

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Active Directory Graph Reconnaissance" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domainName = if ($domain) { $domain.Name } else { $env:USERDNSDOMAIN }
Write-Host "  [+] Current Domain : $domainName" -ForegroundColor Green

if ($doUsers) {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=user)(!(objectClass=computer)))"
    $searcher.PageSize = 500
    $users = $searcher.FindAll()
    Write-Host "  [+] User accounts : $($users.Count)" -ForegroundColor White
}

if ($doComputers) {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(objectClass=computer)"
    $searcher.PageSize = 500
    $computers = $searcher.FindAll()
    Write-Host "  [+] Computer accounts : $($computers.Count)" -ForegroundColor White
}

if ($doGroups) {
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(objectClass=group)"
    $searcher.PageSize = 500
    $groups = $searcher.FindAll()
    Write-Host "  [+] Domain groups : $($groups.Count)" -ForegroundColor White
    Write-Host "`n[High-value Group Membership Snapshot]" -ForegroundColor Yellow
    foreach ($group in $groups) {
        $name = $group.Properties['samaccountname'][0]
        if ($name -match '^(Domain Admins|Enterprise Admins|Schema Admins|Account Operators|Backup Operators)$') {
            $members = $group.Properties['member']
            Write-Host "  [*] $name ($($members.Count) members)" -ForegroundColor Yellow
            foreach ($member in $members) { Write-Host "      - $member" -ForegroundColor Gray }
        }
    }
}

if ($doSessions) {
    Write-Host "`n[Local Interactive/Network/RDP Sessions]" -ForegroundColor Yellow
    $sessions = @(Get-CimInstance Win32_LogonSession -ErrorAction SilentlyContinue |
        Where-Object { $_.LogonType -in @(2, 3, 10) } |
        ForEach-Object {
            $session = $_
            Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch '^(DWM-|UMFD-)' -and $_.Name } |
                ForEach-Object {
                    [PSCustomObject]@{
                        User = "$($_.Domain)\$($_.Name)"
                        LogonType = $session.LogonType
                    }
                }
        })
    $sessions | Sort-Object User, LogonType -Unique | ForEach-Object {
        Write-Host "  [*] $($_.User) (type $($_.LogonType)) on $env:COMPUTERNAME" -ForegroundColor Gray
    }
    Write-Host "  [+] Local session records : $($sessions.Count)" -ForegroundColor White
}

Write-Host "`n  [*] AD graph reconnaissance complete." -ForegroundColor Cyan
Write-Host "  [i] This summary is not a BloodHound CE import archive." -ForegroundColor DarkGray
'''
        markers = {
            "__DO_USERS__": "$true" if "user" in selected else "$false",
            "__DO_COMPUTERS__": "$true" if "computer" in selected else "$false",
            "__DO_GROUPS__": "$true" if "group" in selected else "$false",
            "__DO_SESSIONS__": "$true" if "session" in selected else "$false",
        }
        for marker, value in markers.items():
            ps = ps.replace(marker, value)

        encoded = b64str(ps.encode("utf-16le"))
        command = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        if shell.run_with_interrupt(command, shell.write_line):
            return {"status": "interrupted"}
        return {"status": "completed", "methods": sorted(selected)}
