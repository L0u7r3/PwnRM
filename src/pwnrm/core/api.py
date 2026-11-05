"""
core.api — public CLI argument parser & transport factory
"""

import logging
import os
import re
from argparse     import ArgumentParser, RawDescriptionHelpFormatter, Namespace, ArgumentTypeError
from urllib.parse import urlparse
from typing import Optional, Union

from impacket.examples.utils import parse_target

from .credentials import NTCredential, KrbCredential
from .transports  import (Transport, ClientCertTransport, KerberosTransport,
                          CredSSPTransport, SPNEGOTransport)
from .utils       import load_kerberos_ccache, load_pfx, prepare_kerberos_ccache


def argument_parser() -> ArgumentParser:
    def port_number(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise ArgumentTypeError("port must be an integer") from exc
        if not 1 <= parsed <= 65535:
            raise ArgumentTypeError("port must be between 1 and 65535")
        return parsed

    def positive_timeout(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as exc:
            raise ArgumentTypeError("timeout must be an integer") from exc
        if parsed <= 0:
            raise ArgumentTypeError("timeout must be greater than zero")
        return parsed

    parser = ArgumentParser(
        prog="pwnrm",
        description="PwnRM v2.1.0 — WinRM shell and Active Directory assessment toolkit",
        formatter_class=RawDescriptionHelpFormatter,
        epilog=(
            "Shell commands (once connected):\n"
            "  !session   [list|switch|save|exec-all]   Multi-session manager & jump graph\n"
            "  !socks     [PORT|stop|status]            Direct local SOCKS5 proxy\n"
            "  !portfwd   [LPORT RHOST:RPORT|list|stop] Direct local TCP forwarder\n"
            "  !ligolo    [--remote] AGENT [ARG..]      Detached in-memory Ligolo-ng agent\n"
            "  !module    [list|run <name>]             Extensible module & plugin subsystem\n"
            "  !adcs      [-q|--template <T>|--wsus]    ADCS CA/template/ACL & WSUS triage\n"
            "  !kerberos  [--roast|--asrep|--dmsa]      Kerberos exposure and dMSA triage\n"
            "  !entra     [-s]                          Entra join-state and cache inventory\n"
            "  !creds     [--vault|--dpapi|--lsa]       Credential artifacts and LSASS dump staging\n"
            "  !laps      [-a|--encrypted]              Windows LAPS hunter (Legacy & Server 2025)\n"
            "  !acl       [--target <T>|--tier0]        Active Directory DACL & privilege escalation scout\n"
            "  !token     [--list|--privs]              Process token inventory & privilege audit\n"
            "  !vss       [sam|ntds] [--drive C:]       WMI VSS hive/database staging\n"
            "  !coerce    --listener <IP> [--method M]  Outbound WebDAV/SMB auth probe\n"
            "  !bloodhound [-c <methods>]               AD graph reconnaissance summary\n"
            "  !lateral   [--subnet <s>]                Bounded subnet and service scout\n"
            "  !evasion   [--edr|--amsi|--etw]          Runtime AMSI/ETW patch & EDR scout\n"
            "  !playbook  [--list|--run <name>]         Declarative red team playbook runner\n"
            "  !loot                                    View organized credentials & artifacts\n"
            "  !opsec     [stealth|balanced|aggressive] Toggle execution jitter & profile\n"
            "  !download  RPATH [LPATH]                 Pull file/dir from target\n"
            "  !upload    [-xor] LPATH                  Push file to target\n"
            "  !amsi                                    Patch AmsiScanBuffer in-process\n"
            "  !psrun     [-xor] URL                    Load & exec remote PS1\n"
            "  !netrun    [-xor] URL [ARG]              Load & exec remote .NET assembly\n"
            "  !noconsolation [--capture|--detached] SRC In-memory PE execution mode\n"
            "  !revshell  IP PORT                       Raw Winsock reverse shell\n"
            "\n"
            "Examples:\n"
            "  pwnrm -u Administrator -p 'P@ss1' 192.168.1.10\n"
            "  pwnrm -u user@DOMAIN -k --ccache /tmp/user.ccache dc01.domain.local\n"
            "  pwnrm -u user@DOMAIN --pfx user.pfx --pfx-pass secret https://dc01:5986"
        ),
    )
    parser.add_argument("target",
        help="[[domain/]username[:password]@] <host> or plain <host>")
    # Auth
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("-u", "--username", default="", help="Username (overrides target string)")
    auth.add_argument("-p", "--password", default="", help="Password")
    auth.add_argument("-d", "--domain",   default="", help="Domain / workgroup")
    auth.add_argument("-H", "--hash",     metavar="NTHASH",
        help="NT hash for Pass-the-Hash (format: [LM:]NT or :NT)")
    auth.add_argument("-k", "--kerberos", action="store_true",
        help="Use Kerberos transport (requires valid ccache or KRB5CCNAME)")
    auth.add_argument("--ccache",        metavar="FILE",
        help="Path to .ccache file (default: $KRB5CCNAME)")
    auth.add_argument("--pfx",           metavar="FILE",
        help="Client certificate (.pfx) for HTTPS mutual-auth")
    auth.add_argument("--pfx-pass",      metavar="PASS", default="",
        help="Passphrase for --pfx")
    auth.add_argument("--credssp",       action="store_true",
        help="Force CredSSP transport (delegates credentials)")
    # Connection
    conn = parser.add_argument_group("Connection")
    conn.add_argument("--port",    type=port_number, default=0,
        help="Override WinRM port (default: 5985 HTTP / 5986 HTTPS)")
    conn.add_argument("--ssl",     action="store_true",
        help="Force HTTPS even on non-standard port")
    conn.add_argument("--no-ssl-verify", action="store_true",
        help="Skip TLS certificate verification (verification is enabled by default)")
    conn.add_argument("--timeout", type=positive_timeout, default=30,
        help="Per-request timeout in seconds (default: 30)")
    # Execution
    parser.add_argument("-X", metavar="CMD",
        help="Execute single command and exit (non-interactive)")
    parser.add_argument("--replay", metavar="LOGFILE",
        help="Dead Reckoning replay mode: replay command sequence from session transcript log")
    # Misc
    parser.add_argument("--ts",    action="store_true", help="Add timestamps to log output")
    parser.add_argument("--debug", action="store_true", help="Verbose / debug output")
    return parser


def create_transport(args: Namespace) -> Transport:
    """
    Resolves credentials and returns the appropriate Transport instance.
    Priority:
       1. --pfx            → ClientCertTransport   (ADCS cert-based auth)
       2. --kerberos / -k  → KerberosTransport     (ccache or KRB5CCNAME)
       3. --credssp        → CredSSPTransport       (full cred delegation)
       4. default          → SPNEGOTransport        (NTLM or Kerberos via SPNEGO)
    """
    selected_auth = sum(bool(value) for value in (
        getattr(args, "pfx", None),
        getattr(args, "kerberos", False),
        getattr(args, "credssp", False),
    ))
    if selected_auth > 1:
        raise ValueError("choose only one of --pfx, --kerberos, or --credssp")

    target_clean = args.target
    if target_clean.startswith("http://") or target_clean.startswith("https://"):
        u = urlparse(target_clean)
        host = u.hostname or ""
        domain, username, password = "", u.username or "", u.password or ""
        target_port = u.port
    else:
        domain, username, password, host = parse_target(target_clean)
        target_port = None

    if not host:
        raise ValueError("target host is empty")

    if args.domain:   domain   = args.domain
    if args.username: username = args.username
    if args.password: password = args.password

    use_ssl = args.ssl or bool(getattr(args, "pfx", None)) or (args.port == 5986) or \
              (urlparse(args.target).scheme == "https")
    port    = args.port or target_port or (5986 if use_ssl else 5985)
    scheme  = "https" if use_ssl else "http"
    url     = f"{scheme}://{host}:{port}/wsman"

    def configured(transport: Transport) -> Transport:
        transport.session.verify = not bool(getattr(args, "no_ssl_verify", False))
        return transport

    # 1. Client certificate (.pfx)
    if getattr(args, "pfx", None):
        if getattr(args, "hash", None):
            raise ValueError("--hash cannot be combined with client-certificate authentication")
        import atexit, os as _os, shutil as _shutil
        cert_pem, key_pem = load_pfx(args.pfx, getattr(args, "pfx_pass", "") or None)
        logging.info(f"[+] Using client-cert transport ({args.pfx})")
        # load_pfx() stores both PEM files in a dedicated temp dir;
        # remove the entire directory on exit to ensure no key material lingers on disk.
        _tmp_dir = _os.path.dirname(cert_pem)
        atexit.register(lambda d=_tmp_dir: _shutil.rmtree(d, ignore_errors=True))
        return configured(ClientCertTransport(url, cert_pem, key_pem))

    # 2. Kerberos (ccache)
    if getattr(args, "kerberos", False):
        if getattr(args, "hash", None):
            raise ValueError("--hash cannot be combined with Kerberos ccache authentication")
        ccache_path = getattr(args, "ccache", None) or os.environ.get("KRB5CCNAME", "")
        dom, user, ticket, tgskey = load_kerberos_ccache(ccache_path, target_host=host)
        domain   = domain   or dom
        username = username or user
        logging.info(f"[+] Kerberos transport as {domain}\\{username}")
        if ccache_path and ":" not in ccache_path:
            ccache_path = f"FILE:{os.path.abspath(ccache_path)}"
        ccache_path = prepare_kerberos_ccache(ccache_path, ticket)
        creds = KrbCredential(
            domain, username, ticket, tgskey,
            password=password, ccache=ccache_path,
        )
        return configured(KerberosTransport(url, creds))

    def parsed_nt_hash() -> str:
        raw = (getattr(args, "hash", "") or "").strip()
        if not raw:
            return ""
        parts = raw.split(":")
        if len(parts) == 1:
            lm_hash, nt_hash = "", parts[0]
        elif len(parts) == 2:
            lm_hash, nt_hash = parts
        else:
            raise ValueError("NT hash must use NT or LM:NT format")
        hex32 = re.compile(r"[0-9a-fA-F]{32}")
        if (lm_hash and not hex32.fullmatch(lm_hash)) or not hex32.fullmatch(nt_hash):
            raise ValueError("NT hash must contain exactly 32 hexadecimal characters")
        return nt_hash.lower()

    # 3. CredSSP
    if getattr(args, "credssp", False):
        nt_hash = parsed_nt_hash()
        if nt_hash:
            raise ValueError("CredSSP requires a plaintext password; pass-the-hash is not supported")
        creds = NTCredential(domain, username, password, nt_hash)
        logging.info(f"[+] CredSSP transport as {domain}\\{username}")
        if not username or not password:
            raise ValueError("CredSSP requires a username and plaintext password")
        return configured(CredSSPTransport(url, creds))

    # 4. Default: SPNEGO
    nt_hash = parsed_nt_hash()
    creds = NTCredential(domain, username, password, nt_hash)
    auth_method = "PtH" if nt_hash else "NTLM"
    logging.info(f"[+] SPNEGO transport as {domain}\\{username} ({auth_method})")
    if not username:
        raise ValueError("NTLM/SPNEGO authentication requires a username")
    if not password and not nt_hash:
        raise ValueError("NTLM/SPNEGO authentication requires a password or NT hash")
    return configured(SPNEGOTransport(url, creds))
