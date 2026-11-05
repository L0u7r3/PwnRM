"""PwnRM — WinRM execution and authorized AD assessment toolkit.

The package provides a pypsrp-backed interactive shell, multi-session command
fan-out, direct operator-side TCP proxies, artifact handling, and focused
Active Directory/Windows reconnaissance modules.
"""

__version__ = "2.1.0"
__author__  = "uziii2208"

from .core import (
    Runspace, create_transport, argument_parser,
    NTCredential, KrbCredential, TransportError, SPNEGOError,
    Transport, BasicTransport, ClientCertTransport,
    SPNEGOTransport, KerberosTransport, CredSSPTransport, WebSocketTransport,
    SessionManager, SessionNode, Socks5Server, PortForwarder,
    LootManager, OPSECProfile,
)
from .shell import PwnShell
from .modules import BaseModule, ModuleManager

__all__ = [
    "__version__",
    # core
    "NTCredential", "KrbCredential", "TransportError", "SPNEGOError",
    "Transport", "BasicTransport", "ClientCertTransport",
    "SPNEGOTransport", "KerberosTransport", "CredSSPTransport", "WebSocketTransport",
    "Runspace", "argument_parser", "create_transport",
    "SessionManager", "SessionNode",
    "Socks5Server", "PortForwarder",
    "LootManager", "OPSECProfile",
    # shell
    "PwnShell",
    # modules
    "BaseModule", "ModuleManager",
]
