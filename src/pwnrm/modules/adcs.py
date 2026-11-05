"""Active Directory Certificate Services configuration triage."""

from typing import List, Any

from . import BaseModule
from ..shell.ui import c, M, BLD
from ..shell.commands import b64str


class ADCSModule(BaseModule):
    name = "adcs"
    description = "ADCS CA health, template prerequisite/ACL and WSUS policy triage"
    author = "uziii2208"
    options = {
        "--quick": {"desc": "Skip template ACLs, CA certificate parsing and WSUS policy"},
        "--template": {"desc": "Inspect one certificate template by CN"},
        "--ca": {"desc": "Inspect one Enterprise CA by CN"},
        "--alt": {"desc": "Annotate matching findings with a proposed SAN (no request is sent)"},
        "--wsus": {"desc": "Include WSUS client policy and code-signing template correlation"},
    }

    def run(self, shell, args: List[str]) -> Any:
        quick = False
        force_wsus = False
        values = {"--template": "", "--ca": "", "--alt": ""}
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg in {"-q", "--quick"}:
                quick = True
                idx += 1
                continue
            if arg == "--wsus":
                force_wsus = True
                idx += 1
                continue
            if arg in values:
                if idx + 1 >= len(args) or not args[idx + 1].strip():
                    shell.write_warning(f"  [-] {arg} requires a value.")
                    return {"status": "error", "error": f"missing value for {arg}"}
                values[arg] = args[idx + 1]
                idx += 2
                continue
            shell.write_warning(f"  [-] Unknown ADCS option: {arg}")
            return {"status": "error", "error": "invalid option"}

        shell.write_info(c(M + BLD, "  [*] PwnRM ADCS Engine — auditing CA, template and enrollment controls..."))
        encoded_values = {
            key: b64str(value.encode("utf-8")) if value else ""
            for key, value in values.items()
        }

        ps = r'''
$ErrorActionPreference = 'SilentlyContinue'
$quick = __QUICK__
$doWsus = __DO_WSUS__
$targetTemplate = if ('__TEMPLATE__') { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__TEMPLATE__')) } else { '' }
$targetCA = if ('__CA__') { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__CA__')) } else { '' }
$proposedSAN = if ('__ALT__') { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ALT__')) } else { '' }

Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM ADCS Configuration & Enrollment Triage" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

$rootDSE = [ADSI]'LDAP://RootDSE'
$configNC = [string]$rootDSE.configurationNamingContext
$defaultNC = [string]$rootDSE.defaultNamingContext
if (-not $configNC) { Write-Error 'Unable to read the Configuration naming context.'; return }

$publishedTemplates = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$caMatches = 0
Write-Host '[Enterprise Certification Authorities]' -ForegroundColor Yellow
$caSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"))
$caSearcher.Filter = '(objectClass=pKIEnrollmentService)'
foreach ($ca in $caSearcher.FindAll()) {
    $entry = $ca.GetDirectoryEntry()
    $name = [string]$entry.cn.Value
    if ($targetCA -and $name -ine $targetCA) { continue }
    $caMatches++
    $dns = [string]$entry.dNSHostName.Value
    $templates = @($entry.certificateTemplates)
    foreach ($templateName in $templates) { $null = $publishedTemplates.Add([string]$templateName) }
    Write-Host "  - $name on $dns ($($templates.Count) published templates)" -ForegroundColor White
    if (-not $quick -and $entry.cACertificate.Value) {
        try {
            $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$entry.cACertificate.Value)
            $color = if ($certificate.NotAfter -lt (Get-Date)) { 'Red' } else { 'Green' }
            Write-Host "    Certificate expires: $($certificate.NotAfter)" -ForegroundColor $color
        } catch { Write-Host "    [-] CA certificate could not be decoded." -ForegroundColor Yellow }
    }
}
if ($caMatches -eq 0) { Write-Host "  [-] No Enterprise CA matched the requested filter." -ForegroundColor Yellow }

$domainSid = $null
try {
    $domainEntry = [ADSI]("LDAP://$defaultNC")
    $domainSid = [System.Security.Principal.SecurityIdentifier]::new([byte[]]$domainEntry.objectSid.Value, 0).Value
} catch {}
$lowPrivilegeSids = @('S-1-1-0', 'S-1-5-11')
if ($domainSid) { $lowPrivilegeSids += "$domainSid-513", "$domainSid-515" }
$enrollGuid = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$autoEnrollGuid = [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

Write-Host "`n[Certificate Template Prerequisites & ACLs]" -ForegroundColor Yellow
$templateSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]("LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"))
$templateSearcher.Filter = '(objectClass=pKICertificateTemplate)'
$templateMatches = 0
$indicatorCount = 0
foreach ($result in $templateSearcher.FindAll()) {
    $entry = $result.GetDirectoryEntry()
    $name = [string]$entry.cn.Value
    if ($targetTemplate -and $name -ine $targetTemplate) { continue }
    $templateMatches++
    $displayName = [string]$entry.displayName.Value
    $nameFlags = [int]$entry.'msPKI-Certificate-Name-Flag'.Value
    $ekus = @($entry.'pKIExtendedKeyUsage' | ForEach-Object { [string]$_ })
    $suppliesSubject = ($nameFlags -band 1) -ne 0
    $clientAuth = @($ekus | Where-Object { $_ -in @('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.2.3.4', '1.3.6.1.4.1.311.20.2.2') }).Count -gt 0
    $anyPurpose = $ekus.Count -eq 0 -or $ekus -contains '2.5.29.37.0'
    $requestAgent = $ekus -contains '1.3.6.1.4.1.311.20.2.1'
    $codeSigning = @($ekus | Where-Object { $_ -in @('1.3.6.1.5.5.7.3.3', '1.3.6.1.4.1.311.10.3.6', '1.3.6.1.4.1.311.76.7.1') }).Count -gt 0
    $published = $publishedTemplates.Contains($name)
    $lowPrivControl = $false
    $lowPrivTrustees = @()

    if (-not $quick) {
        try {
            $rules = $entry.ObjectSecurity.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            foreach ($rule in $rules) {
                $sid = $rule.IdentityReference.Value
                if ($rule.AccessControlType -ne 'Allow' -or $sid -notin $lowPrivilegeSids) { continue }
                $rights = [string]$rule.ActiveDirectoryRights
                $objectType = $rule.ObjectType
                $broadControl = $rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner'
                $enrollRight = $rights -match 'ExtendedRight' -and ($objectType -eq [Guid]::Empty -or $objectType -eq $enrollGuid -or $objectType -eq $autoEnrollGuid)
                if ($broadControl -or $enrollRight) { $lowPrivControl = $true; $lowPrivTrustees += $sid }
            }
        } catch { Write-Host "  [-] Could not read ACL for template '$name'." -ForegroundColor Yellow }
    }

    $signals = @()
    if ($suppliesSubject -and $clientAuth) { $signals += 'ESC1 prerequisites (subject/SAN supply + client authentication)' }
    if ($anyPurpose) { $signals += 'ESC2 prerequisites (Any Purpose or no EKU restriction)' }
    if ($requestAgent) { $signals += 'ESC3 prerequisite (Certificate Request Agent EKU)' }
    if ($codeSigning) { $signals += 'Code-signing / Windows Update EKU' }
    if ($signals.Count -eq 0 -and -not $targetTemplate) { continue }

    $indicatorCount += $signals.Count
    Write-Host "  [*] $name ($displayName)" -ForegroundColor White
    Write-Host "      Published by selected CA(s): $published" -ForegroundColor Gray
    foreach ($signal in $signals) { Write-Host "      - $signal" -ForegroundColor Yellow }
    if ($quick) {
        Write-Host '      - ACL not evaluated in quick mode' -ForegroundColor DarkGray
    } elseif ($lowPrivControl) {
        Write-Host "      [!] Low-privilege enrollment/control ACE: $($lowPrivTrustees -join ', ')" -ForegroundColor Red
    } else {
        Write-Host '      [+] No direct low-privilege enrollment/control ACE matched the built-in principals.' -ForegroundColor Green
    }
    if ($proposedSAN -and $suppliesSubject) { Write-Host "      Proposed SAN annotation: $proposedSAN (no request sent)" -ForegroundColor Magenta }
}
if ($templateMatches -eq 0) {
    Write-Host '  [-] No certificate template matched the requested filter.' -ForegroundColor Yellow
} elseif ($indicatorCount -eq 0) {
    Write-Host '  [+] No implemented ESC1/2/3 or code-signing prerequisite was found.' -ForegroundColor Green
}

if ($doWsus) {
    Write-Host "`n[Local WSUS Client Policy]" -ForegroundColor Yellow
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (Test-Path -LiteralPath $path) {
        $server = (Get-ItemProperty -LiteralPath $path -Name WUServer -ErrorAction SilentlyContinue).WUServer
        $acceptTrusted = (Get-ItemProperty -LiteralPath "$path\AU" -Name AcceptTrustedPublisherCerts -ErrorAction SilentlyContinue).AcceptTrustedPublisherCerts
        Write-Host "  WUServer: $(if ($server) { $server } else { '<unset>' })" -ForegroundColor White
        Write-Host "  AcceptTrustedPublisherCerts: $(if ($null -eq $acceptTrusted) { '<unset>' } else { $acceptTrusted })" -ForegroundColor White
        if ($server -match '^http://' -and $acceptTrusted -eq 1) { Write-Host '  [!] Cleartext WSUS plus trusted publisher certificates requires immediate review.' -ForegroundColor Red }
    } else { Write-Host '  [-] No local WSUS policy was found.' -ForegroundColor Gray }
}

Write-Host "`n  [*] ADCS configuration triage complete." -ForegroundColor Cyan
Write-Host '  [i] Prerequisite matches are not exploitable findings without publication, ACL and CA-policy validation.' -ForegroundColor DarkGray
'''
        replacements = {
            "__QUICK__": "$true" if quick else "$false",
            "__DO_WSUS__": "$true" if (force_wsus or not quick) else "$false",
            "__TEMPLATE__": encoded_values["--template"],
            "__CA__": encoded_values["--ca"],
            "__ALT__": encoded_values["--alt"],
        }
        for marker, value in replacements.items():
            ps = ps.replace(marker, value)

        encoded = b64str(ps.encode("utf-16le"))
        command = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        if shell.run_with_interrupt(command, shell.write_line):
            return {"status": "interrupted"}
        return {
            "status": "completed",
            "quick": quick,
            "template": values["--template"],
            "ca": values["--ca"],
            "wsus": force_wsus or not quick,
        }
