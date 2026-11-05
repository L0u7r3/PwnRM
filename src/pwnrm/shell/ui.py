"""
shell.ui — ANSI colors, banner, tab-completion word list
"""

# ── ANSI palette ─────────────────────────────────────────────────────────────
R   = "\x1b[31m";  G   = "\x1b[32m";  Y   = "\x1b[33m"
B   = "\x1b[34m";  M   = "\x1b[35m";  C   = "\x1b[36m"
W   = "\x1b[37m";  DIM = "\x1b[2m";   BLD = "\x1b[1m"
RST = "\x1b[0m"

def c(col, s):
    return f"{col}{s}{RST}"

G1 = "\x1b[38;5;237m"
G2 = "\x1b[38;5;241m"
G3 = "\x1b[38;5;245m"
G4 = "\x1b[38;5;249m"
G5 = "\x1b[38;5;253m"
G6 = "\x1b[38;5;255m"

_BANNER = rf"""
{BLD}
{G1}██████╗ ██╗    ██╗███╗   ██╗██████╗ ███╗   ███╗
{G2}██╔══██╗██║    ██║████╗  ██║██╔══██╗████╗ ████║
{G3}██████╔╝██║ █╗ ██║██╔██╗ ██║██████╔╝██╔████╔██║
{G4}██╔═══╝ ██║███╗██║██║╚██╗██║██╔══██╗██║╚██╔╝██║
{G5}██║     ╚███╔███╔╝██║ ╚████║██║  ██║██║ ╚═╝ ██║
{G6}╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝
{RST}{DIM}    WinRM / Active Directory Assessment Toolkit  {BLD}v2.1.0{RST}
{DIM}  github.com/L0u7r3/PwnRM  ·  fork of uziii2208/PwnRM  ·  Authorized use only.{RST}
"""

# ── Tab-completion word list ──────────────────────────────────────────────────
_COMPLETIONS = [
    "!session", "!socks", "!portfwd", "!ligolo",
    "!module", "!adcs", "!kerberos", "!entra", "!creds", "!token",
    "!laps", "!acl", "!vss", "!coerce",
    "!bloodhound", "!lateral", "!playbook", "!loot", "!opsec", "!evasion",
    "!download", "!upload", "!amsi", "!psrun", "!netrun", "!noconsolation",
    "!revshell", "!log", "!stoplog", "!adtriage", "!shares",
    "!sessions", "!sysinfo", "!help", "exit", "quit",
    # canonical command modes and long options:
    "list", "run", "switch", "save", "exec-all", "stop", "status",
    "roast", "asrep", "rbcd", "dmsa", "diamond", "full",
    "vault", "dpapi", "decrypt", "history", "browser", "lsa",
    "all", "encrypted", "tier0", "privs", "sam", "ntds",
    "webdav", "smb", "edr", "amsi", "etw", "native", "managed",
    "--quick", "--template", "--ca", "--alt", "--wsus", "--target",
    "--collection", "--subnet", "--ports", "--probe-auth", "--listener",
    "--port", "--drive", "--file", "--lsa-output", "--download", "--xor", "--remote",
    "--capture-output", "--detached", "--timeout",
    # common PS one-liners operators may want fast access to:
    "Get-Process", "Get-Service", "whoami", "ipconfig", "net user",
    "net localgroup administrators", "systeminfo", "Get-NetIPAddress",
]
