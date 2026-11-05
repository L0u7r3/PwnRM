"""Kerberos exposure, delegation, dMSA, and ticket-tooling prerequisite triage."""

from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class KerberosModule(BaseModule):
    name = "kerberos"
    description = "Kerberos exposure triage (SPN/AS-REP candidates, RBCD, dMSA and Diamond prerequisites)"
    author = "uziii2208"
    options = {
        "roast": {"desc": "Enumerate enabled user SPNs and their advertised encryption types"},
        "asrep": {"desc": "Enumerate accounts vulnerable to AS-REP roasting (DONT_REQ_PREAUTH)"},
        "rbcd": {"desc": "Enumerate Resource-Based Constrained Delegation (RBCD) targets"},
        "dmsa": {"desc": "Audit Server 2025 Delegated Managed Service Accounts (dMSA)"},
        "diamond": {"desc": "Display the current domain prerequisites required for Diamond Ticket tooling"},
    }

    def run(self, shell, args: List[str]) -> Any:
        legacy_modes = {f"--{mode}": mode for mode in self.options}
        normalized = [legacy_modes.get(arg.lower(), arg.lower()) for arg in args]
        valid = set(self.options)
        unknown = [arg for arg in normalized if arg not in valid]
        if unknown:
            shell.write_warning(f"  [-] Unknown Kerberos option(s): {', '.join(unknown)}")
            return {"status": "error", "error": "invalid options"}
        selected = set(normalized) if normalized else {"roast", "asrep", "rbcd", "dmsa"}
        shell.write_info(c(M + BLD, "  [*] PwnRM Kerberos Suite — initializing Kerberos triage..."))

        ps = r"""
$ErrorActionPreference = 'SilentlyContinue'
$doRoast = __DO_ROAST__
$doAsrep = __DO_ASREP__
$doRbcd = __DO_RBCD__
$doDmsa = __DO_DMSA__
$doDiamond = __DO_DIAMOND__
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Kerberos Exposure & Delegation Triage" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. AS-REP Roasting (DONT_REQ_PREAUTH = 0x400000 / 4194304)
if ($doAsrep) {
Write-Host "[1. AS-REP Roasting Candidates (DONT_REQ_PREAUTH)]" -ForegroundColor Yellow
$asrepSearcher = New-Object System.DirectoryServices.DirectorySearcher
$asrepSearcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$asreps = $asrepSearcher.FindAll()

if ($asreps.Count -eq 0) {
    Write-Host "  [+] No AS-REP roastable accounts found in domain." -ForegroundColor Green
} else {
    foreach ($a in $asreps) {
        $u = $a.Properties["samaccountname"][0]
        $spn = $a.Properties["serviceprincipalname"]
        Write-Host "  [!] AS-REP Roastable: $u" -ForegroundColor Red
        if ($spn) { Write-Host "      SPN: $spn" -ForegroundColor Gray }
    }
}
}

# 2. Kerberoast candidate enumeration with encryption-type visibility
if ($doRoast) {
Write-Host "`n[2. SPN Accounts / Kerberoast Targets]" -ForegroundColor Yellow
$spnSearcher = New-Object System.DirectoryServices.DirectorySearcher
$spnSearcher.Filter = "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
$spns = $spnSearcher.FindAll()

if ($spns.Count -eq 0) {
    Write-Host "  [+] No user SPN targets found for Kerberoasting." -ForegroundColor Green
} else {
    foreach ($s in $spns) {
        $u = $s.Properties["samaccountname"][0]
        $spnList = $s.Properties["serviceprincipalname"]
        $encTypes = [int]$s.Properties["msds-supportedencryptiontypes"][0]
        $encStr = "RC4"
        if (($encTypes -band 0x10) -ne 0 -or ($encTypes -band 0x08) -ne 0) {
            $encStr = "AES (AES128/AES256 supported)"
        }
        Write-Host "  [!] User SPN: $u ($encStr)" -ForegroundColor Yellow
        foreach ($p in $spnList) {
            Write-Host "      - $p" -ForegroundColor Gray
        }
    }
}
}

# 3. RBCD (Resource-Based Constrained Delegation) & Delegation Scout
if ($doRbcd) {
Write-Host "`n[3. Resource-Based Constrained Delegation (RBCD) Targets]" -ForegroundColor Yellow
$rbcdSearcher = New-Object System.DirectoryServices.DirectorySearcher
$rbcdSearcher.Filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
$rbcdTargets = $rbcdSearcher.FindAll()

if ($rbcdTargets.Count -eq 0) {
    Write-Host "  [+] No RBCD-configured objects discovered." -ForegroundColor Green
} else {
    foreach ($r in $rbcdTargets) {
        $u = $r.Properties["samaccountname"][0]
        Write-Host "  [!] RBCD Configured Target: $u (msDS-AllowedToActOnBehalfOfOtherIdentity present)" -ForegroundColor Red
    }
}
}

# 4. Server 2025 dMSA & gMSA Inspection
if ($doDmsa) {
Write-Host "`n[4. Server 2025 dMSA / BadSuccessor & gMSA Accounts]" -ForegroundColor Yellow
$gmsaSearcher = New-Object System.DirectoryServices.DirectorySearcher
$gmsaSearcher.Filter = "(|(objectClass=msDS-DelegatedManagedServiceAccount)(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))"
$null = $gmsaSearcher.PropertiesToLoad.Add("samAccountName")
$null = $gmsaSearcher.PropertiesToLoad.Add("objectClass")
$null = $gmsaSearcher.PropertiesToLoad.Add("msDS-DelegatedMSAState")
$null = $gmsaSearcher.PropertiesToLoad.Add("msDS-ManagedAccountPrecededByLink")
$null = $gmsaSearcher.PropertiesToLoad.Add("msDS-GroupMSAMembership")
$gmsas = $gmsaSearcher.FindAll()

if ($gmsas.Count -eq 0) {
    Write-Host "  [+] No gMSA/dMSA accounts discovered in domain." -ForegroundColor Green
} else {
    foreach ($g in $gmsas) {
        $u = $g.Properties["samaccountname"][0]
        $cls = $g.Properties["objectclass"]
        Write-Host "  [*] Managed Service Account: $u ($cls)" -ForegroundColor Cyan
        if ($cls -contains "msDS-DelegatedManagedServiceAccount") {
            $state = $g.Properties["msds-delegatedmsastate"][0]
            $predecessor = $g.Properties["msds-managedaccountprecededbylink"][0]
            Write-Host "      - dMSA state             : $state (1=migration started, 2=completed, 3=standalone)" -ForegroundColor Gray
            Write-Host "      - Preceded by account    : $(if ($predecessor) { $predecessor } else { '<none>' })" -ForegroundColor Gray
        }
    }
}
}

# 5. Diamond Ticket prerequisite summary. PwnRM does not request or forge a
# ticket here: the operator must supply a krbtgt key to a dedicated ticket tool.
if ($doDiamond) {
    Write-Host "`n[5. Diamond Ticket Prerequisites]" -ForegroundColor Yellow
    $root = [ADSI]"LDAP://RootDSE"
    $domainEntry = [ADSI]("LDAP://" + $root.defaultNamingContext)
    $domainSid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$domainEntry.objectSid.Value, 0).Value
    Write-Host "  Domain DNS name : $($env:USERDNSDOMAIN)" -ForegroundColor White
    Write-Host "  Domain SID      : $domainSid" -ForegroundColor White
    Write-Host "  Required input  : krbtgt AES256/RC4 key acquired through an authorized workflow" -ForegroundColor Gray
    Write-Host "  [*] No ticket was forged or injected by this reconnaissance module." -ForegroundColor Cyan
}

Write-Host "`n  [*] Kerberos triage complete." -ForegroundColor Cyan
"""
        replacements = {
            "__DO_ROAST__": "$true" if "roast" in selected else "$false",
            "__DO_ASREP__": "$true" if "asrep" in selected else "$false",
            "__DO_RBCD__": "$true" if "rbcd" in selected else "$false",
            "__DO_DMSA__": "$true" if "dmsa" in selected else "$false",
            "__DO_DIAMOND__": "$true" if "diamond" in selected else "$false",
        }
        for marker, value in replacements.items():
            ps = ps.replace(marker, value)
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        if shell.run_with_interrupt(cmd, shell.write_line):
            return {"status": "interrupted"}
        return {"status": "completed", "selected": sorted(selected)}
