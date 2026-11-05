# PwnRM

PwnRM is a pypsrp-backed WinRM shell and Windows/Active Directory assessment
toolkit for authorized engagements. This fork repairs the authentication and
dependency stack, supports Impacket S4U service-ticket ccaches, restores
PowerShell 5.1 compatibility, and turns previously decorative module options
into tested behavior.

The original project and authorship belong to
[uziii2208/PwnRM](https://github.com/uziii2208/PwnRM). This maintained fork is
published at [L0u7r3/PwnRM](https://github.com/L0u7r3/PwnRM).

## Installation

PwnRM supports CPython 3.10 through 3.14.

```bash
pipx install 'git+https://github.com/L0u7r3/PwnRM.git'

# Or in a virtual environment
python -m pip install 'git+https://github.com/L0u7r3/PwnRM.git'
python -m pip check
```

For Debian, Ubuntu, or Kali, the repository installer creates an isolated
environment under `/opt/pwnrm`:

```bash
git clone https://github.com/L0u7r3/PwnRM.git
cd PwnRM
sudo bash install.sh
```

Developer setup:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q
python -m pip check
```

## Authentication

```bash
# Password / NTLM
pwnrm -d CORP -u operator -p 'password' dc01.corp.local

# Pass-the-hash; accepts NT or LM:NT
pwnrm -d CORP -u operator -H 31d6cfe0d16ae931b73c59d7e0c089c0 dc01

# Kerberos ccache
pwnrm -k --ccache /tmp/operator.ccache dc01.corp.local

# Impacket S4U service-ticket-only ccache (TERMSRV, WSMAN, HTTP, etc.)
pwnrm -k --ccache /tmp/Administrator@TERMSRV_DC01@CORP.LOCAL.ccache DC01

# CredSSP credential delegation
pwnrm -d CORP -u operator -p 'password' --credssp dc01

# Client certificate; --pfx selects HTTPS/5986 by default
pwnrm --pfx operator.pfx --pfx-pass 'password' dc01

# Single command
pwnrm -k --ccache /tmp/operator.ccache DC01 -X 'whoami'
```

TLS certificates are verified by default. Use `--no-ssl-verify` only when the
engagement explicitly requires it. If the operator clock differs from the KDC,
run PwnRM in a correctly synchronized environment; Kerberos clock-skew rules
still apply.

## Interactive commands

Command modes are bare positional words (`!creds lsa`, `!kerberos roast`).
Options that configure a mode use long `--name` syntax (`--lsa-output PATH`,
`--timeout SEC`). Legacy spellings remain accepted for script compatibility,
but are not the documented interface.

| Command | Implemented behavior |
| --- | --- |
| `!session list\|switch\|save\|exec-all` | Session inventory, switching, encrypted same-process metadata snapshot, concurrent command fan-out |
| `!socks [PORT\|stop\|status]` | Direct local RFC 1928 CONNECT proxy; outbound connections originate from the operator host |
| `!portfwd LPORT RHOST:RPORT` | Direct operator-side TCP forward; use `list` or `stop <ID\|all>` to manage it |
| `!ligolo [--remote] AGENT [ARG..]` | Launch an operator-supplied Windows Ligolo-ng agent in memory inside a detached target process |
| `!module list\|run <name>` | Built-in and permission-checked external module registry |
| `!adcs` | Enterprise CA health, template publication/prerequisite/ACL, and optional WSUS policy triage |
| `!kerberos` | SPN/AS-REP candidate, RBCD, dMSA, and Diamond prerequisite reconnaissance |
| `!entra [full]` | Entra join/PRT status plus accessible WAM/Azure cache-path inventory |
| `!creds [vault\|dpapi\|decrypt\|history\|browser\|lsa] [--download]` | Credential artifact inventory, DPAPI unprotect, and ephemeral LSASS parsing |
| `!laps [all\|encrypted]` | Legacy and modern Windows LAPS attribute query, including encrypted/DSRM metadata |
| `!acl [tier0] [--target NAME]` | Targeted or Tier-0 AD DACL inspection |
| `!token [list\|privs]` | Current privilege and process-token identity inventory |
| `!bloodhound [--collection METHODS]` | AD graph-oriented reconnaissance summary by collection method |
| `!lateral` | Bounded IPv4 subnet service scan with optional WSMan authentication probe |
| `!vss [sam\|ntds] [--download]` | Ephemeral WMI shadow-copy extraction, local secret display, and immediate remote cleanup |
| `!coerce [webdav\|smb\|all] --listener HOST` | Outbound WebDAV and/or SMB UNC authentication probe as the current remote identity |
| `!evasion [edr\|amsi\|etw]` / `!amsi` | Selected AMSI/ETW in-process patching and EDR/AV inventory |
| `!adtriage`, `!shares`, `!sessions`, `!sysinfo` | PowerShell 5.1-compatible host and AD reconnaissance |
| `!upload`, `!download` | SHA-256-verified file transfer; directory downloads are zipped remotely |
| `!psrun`, `!netrun` | HTTP(S) or remote-path in-memory PowerShell/.NET execution |
| `!noconsolation [native\|managed] [--capture-output\|--detached] ...` | Native PE execution through No-Consolation or managed PE loading; output capture is opt-in |
| `!revshell IPv4 PORT` | Raw IPv4 reverse command shell |
| `!playbook [list\|run NAME\|run --file PATH]` | Validated JSON/built-in sequential automation with conditions and cleanup hooks |
| `!loot`, `!opsec`, `!log`, `!stoplog` | Local artifact inventory, jitter profile, and transcript controls |

Run `pwnrm -h` and `help` inside the shell for the current syntax.

## Important capability boundaries

These distinctions are deliberate and covered by regression tests:

- `!socks` and `!portfwd` are direct local proxies. They do not multiplex TCP
  through PSRP and therefore do not provide a target-side network pivot.
- `!coerce` performs real WebDAV/SMB UNC access probes. It does not implement
  MS-RPRN, MS-EFSR/PetitPotam, or MS-DFSNM RPC calls.
- `!kerberos` enumerates candidates and prerequisites. It does not request
  roastable tickets or forge Diamond tickets.
- `!adcs` triages CA/template conditions and access controls. It does not claim
  complete ESC1–ESC17 exploit validation and does not request certificates.
- `!bloodhound` emits an operator-readable graph reconnaissance summary, not a
  BloodHound CE import archive.
- `!token` inventories tokens and privileges; it does not impersonate another
  identity or elevate the session.
- `!entra` locates accessible authentication artifacts but does not decrypt or
  extract a Primary Refresh Token.
- `!vss` creates no `vssadmin.exe`/`ntdsutil.exe` process. It briefly stages
  copied hives or `ntds.dit`, streams them for local parsing, then verifies
  deletion of the remote staging directory.
- `WebSocketTransport` is retained only as an import-compatible placeholder and
  fails explicitly. Supported runspaces use HTTP(S) through pypsrp.

## Transfer and staging notes

Uploads and downloads use SHA-256 integrity verification and configurable
256 MiB defaults (`PWNRM_MAX_UL`, `PWNRM_MAX_DL`). Local downloads refuse
symbolic-link destinations and are created mode `0600` on POSIX.

`!upload --xor` uses a random key generated for the current PwnRM process. The
corresponding `!psrun --xor` or `!netrun --xor` must run in that same process;
starting another PwnRM instance creates a different key.

`!noconsolation` does not capture output unless `--capture-output` (alias
`--capture`) is present. Without it, PwnRM starts a background runspace, asks
the native loader not to collect output, and returns immediately. That default
job remains tied to the current interactive session. Add `--detached` to move
execution into a WMI-created PowerShell process fed through a named pipe; it
survives RunspacePool closure and returns a target PID for later cleanup.
`--detached` and output capture are mutually exclusive. See the
[runtime documentation](docs/03_evasion_and_runtime_opsec.md#native-and-managed-pe-execution-noconsolation)
for native/managed and local/remote examples.

SAM, NTDS and LSASS extraction streams raw artifacts into protected operator
memory, displays decoded credential material, and immediately removes remote
staging. Raw files are not retained locally unless `--download` is supplied;
retained files are written mode `0600` under the structured PwnRM loot store.

## Python API

```python
from pwnrm import Runspace, PwnShell, argument_parser, create_transport

args = argument_parser().parse_args([
    "-d", "CORP", "-u", "operator", "-p", "password", "dc01"
])

with Runspace(create_transport(args), timeout=args.timeout) as runspace:
    shell = PwnShell(runspace, target_info={"host": args.target})
    result = shell.repl(inputs=["whoami", "!sysinfo"])
    if result and result.get("status") == "error":
        raise RuntimeError(result["error"])
```

See [docs/README.md](docs/README.md) for architecture, module, security, and API
details.

## Security and authorization

PwnRM can execute commands, alter a remote PowerShell process, stage sensitive
files, and trigger outbound authentication. Use it only with explicit written
authorization and within the agreed Rules of Engagement. Review
[SECURITY.md](SECURITY.md) before reporting a vulnerability.

PwnRM is MIT licensed. See [LICENSE.md](LICENSE.md).
