"""
modules.lateral — bounded subnet and service scout
Probes network subnets for exposed WinRM, SMB, WMI, and RDP endpoints with lateral credential & WSMan micro-probing.
"""

from ipaddress import IPv4Network, ip_network
from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import b64str


class LateralModule(BaseModule):
    name = "lateral"
    description = "Bounded subnet service scout (WinRM, SMB/RPC and RDP with optional WSMan auth probing)"
    author = "uziii2208"
    options = {
        "--subnet": {"desc": "Target IPv4 subnet (max 1024 addresses; default: local .1-.30 sample)"},
        "--ports": {"desc": "Custom ports to probe (default: 5985, 5986, 445, 135, 3389)"},
        "--probe-auth": {"desc": "Execute active WinRM WS-Management auth micro-probe"},
    }

    def run(self, shell, args: List[str]) -> Any:
        subnet = None
        ports = [5985, 5986, 445, 135, 3389]
        probe_auth = False
        idx = 0
        while idx < len(args):
            arg = args[idx]
            if arg in {"--subnet", "--ports"}:
                if idx + 1 >= len(args):
                    shell.write_warning(f"  [-] {arg} requires a value.")
                    return {"status": "error", "error": f"missing value for {arg}"}
                value = args[idx + 1]
                if arg == "--subnet":
                    try:
                        parsed = ip_network(value, strict=False)
                    except ValueError:
                        shell.write_warning(f"  [-] Invalid IPv4 subnet: {value}")
                        return {"status": "error", "error": "invalid subnet"}
                    if not isinstance(parsed, IPv4Network):
                        shell.write_warning("  [-] IPv6 subnet scanning is not supported by this module.")
                        return {"status": "error", "error": "IPv6 is unsupported"}
                    if parsed.num_addresses > 1024:
                        shell.write_warning("  [-] Subnet contains more than 1024 addresses; narrow the prefix.")
                        return {"status": "error", "error": "subnet too large"}
                    hosts = list(parsed.hosts())
                    subnet = (str(parsed), [str(host) for host in hosts])
                else:
                    try:
                        requested = [int(port.strip()) for port in value.split(",") if port.strip()]
                    except ValueError:
                        requested = []
                    if not requested or len(requested) > 32 or any(not 1 <= port <= 65535 for port in requested):
                        shell.write_warning("  [-] --ports expects 1-32 comma-separated TCP ports in the range 1-65535.")
                        return {"status": "error", "error": "invalid ports"}
                    ports = list(dict.fromkeys(requested))
                idx += 2
                continue
            if arg == "--probe-auth":
                probe_auth = True
                idx += 1
                continue
            shell.write_warning(f"  [-] Unknown lateral option: {arg}")
            return {"status": "error", "error": "invalid option"}

        shell.write_info(c(M + BLD, "  [*] PwnRM Network Scout — probing the selected network segment..."))

        if subnet:
            target_lines = "\n".join(subnet[1])
            target_setup = f"""
$targets = @(([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64str(target_lines.encode())}'))) -split "`n" | Where-Object {{ $_ }})
$scanLabel = '{subnet[0]}'
"""
        else:
            target_setup = r'''
$prefix = ($localIP -split "\.")[0..2] -join "."
$targets = 1..30 | ForEach-Object { "$prefix.$_" }
$scanLabel = "$prefix.1 - $prefix.30 (fast local sample)"
'''
        port_setup = ", ".join(str(port) for port in ports)
        probe_auth_ps = "$true" if probe_auth else "$false"

        ps = rf"""
$ErrorActionPreference = 'SilentlyContinue'
Write-Host "`n========================================================" -ForegroundColor Cyan
Write-Host "   PwnRM Subnet & Service Scout" -ForegroundColor Cyan
Write-Host "========================================================`n" -ForegroundColor Cyan

# 1. Determine local address and targets
$ipConfig = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {{ $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress -notmatch "^169\." }} | Select-Object -First 1
if (-not $ipConfig) {{
    throw "Could not determine a local IPv4 interface"
}}
$localIP = $ipConfig.IPAddress
{target_setup}
Write-Host "  [+] Local IP Address: $localIP" -ForegroundColor Green
Write-Host "  [*] Probing targets : $scanLabel" -ForegroundColor Gray

$ports = @({port_setup})
$probeAuth = {probe_auth_ps}

foreach ($t in $targets) {{
    if ($t -eq $localIP) {{ continue }}
    foreach ($p in $ports) {{
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($t, $p, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne(100, $false)
        if ($wait) {{
            try {{
                $tcp.EndConnect($iar)
                $proto = switch ($p) {{ 5985 {{"WinRM-HTTP"}} 5986 {{"WinRM-HTTPS"}} 445 {{"SMB"}} 135 {{"MS-RPC"}} 3389 {{"RDP"}} default {{"TCP/$p"}} }}
                
                # If WinRM port, execute WSMan identify micro-probe
                if ($probeAuth -and $p -in @(5985, 5986)) {{
                    $scheme = if ($p -eq 5986) {{ "https" }} else {{ "http" }}
                    $wsmanUrl = "${{scheme}}://$t`:$p/wsman"
                    try {{
                        $req = [System.Net.WebRequest]::Create($wsmanUrl)
                        $req.Method = "POST"
                        $req.Timeout = 500
                        $req.ContentType = "application/soap+xml;charset=UTF-8"
                        $req.UserAgent = "Microsoft WinRM Client"
                        $resp = $req.GetResponse()
                        $statusCode = [int]$resp.StatusCode
                        $resp.Close()
                        Write-Host "  [*] [WSMAN_HTTP_RESPONSE] $t : $p ($proto) — Status $statusCode" -ForegroundColor Yellow
                    }} catch [System.Net.WebException] {{
                        $webResp = $_.Exception.Response
                        if ($webResp) {{
                            $code = [int]$webResp.StatusCode
                            if ($code -eq 401) {{
                                Write-Host "  [+] [WSMAN_AUTH_REQUIRED] $t : $p ($proto) — HTTP 401" -ForegroundColor Green
                            }} else {{
                                Write-Host "  [*] [REACHABLE] $t : $p ($proto) — HTTP Status $code" -ForegroundColor Yellow
                            }}
                            $webResp.Close()
                        }} else {{
                            Write-Host "  [*] [PORT_OPEN] $t : $p ($proto) — TCP Connection Established" -ForegroundColor Gray
                        }}
                    }} catch {{
                        Write-Host "  [*] [PORT_OPEN] $t : $p ($proto) — TCP Connection Established" -ForegroundColor Gray
                    }}
                }} else {{
                    Write-Host "  [+] [PORT_OPEN] $t : $p ($proto)" -ForegroundColor Green
                }}
            }} catch {{}}
        }}
        $tcp.Close()
    }}
}}

Write-Host "`n  [*] Network service scout complete." -ForegroundColor Cyan
"""
        encoded = b64str(ps.encode("utf-16le"))
        cmd = f"Invoke-Expression ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))"
        if shell.run_with_interrupt(cmd, shell.write_line):
            return {"status": "interrupted"}
        return {"status": "completed", "targets": len(subnet[1]) if subnet else 30, "ports": ports}
