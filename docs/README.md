# PwnRM technical documentation

This documentation describes the behavior implemented by the current fork. It
is intentionally conservative: reconnaissance is not described as exploitation,
and a prerequisite check is not described as a vulnerability confirmation.

## Contents

1. [Architecture and core](01_architecture_and_core.md) — CLI, transport
   selection, pypsrp runspaces, command dispatch, sessions, and local proxies.
2. [Identity and AD modules](02_identity_and_ad_abuse.md) — ADCS, Kerberos,
   LAPS, ACL, token, credentials, and Entra behavior and limits.
3. [Runtime and staging](03_evasion_and_runtime_opsec.md) — AMSI/ETW patches,
   transfers, PowerShell/.NET execution, reverse shell, and OPSEC profiles.
4. [Collection and automation](04_collection_lateral_playbooks.md) — triage,
   shares, sessions, BloodHound-oriented summaries, subnet scan, VSS, UNC
   authentication probes, and playbooks.
5. [Python API](05_api_and_c2_integration.md) — supported public entry points
   and integration examples.
6. [Security boundaries](06_security_boundaries_and_hardening.md) — local and
   remote trust boundaries, limits, and validation commands.

## Supported runtime

- CPython 3.10–3.14
- `pypsrp` 0.9.x persistent runspace backend
- Impacket WMI, DCOM, Task Scheduler, SMBExec, and PsExec shell fallbacks
- Windows PowerShell 5.1-compatible generated payloads
- HTTP/HTTPS WinRM with NTLM/SPNEGO, pass-the-hash, Kerberos ccache, CredSSP,
  Basic when constructed through the API, or HTTPS client certificate

TLS verification is enabled by default. HTTP redirects and ambient proxy
environment variables are disabled for WinRM sessions.

## Capability summary

PwnRM provides remote PowerShell execution, S4U ccache support, interruptible
pipelines, multi-session fan-out, SHA-256-verified transfers, in-memory script,
.NET, and native PE loading, explicit LSASS/VSS staging, AD/Windows
reconnaissance modules, and operator-side SOCKS5/TCP forwarding.

The following are explicitly outside the implementation:

- PSRP-carried network tunneling;
- MS-RPRN, MS-EFSR, or MS-DFSNM RPC coercion;
- ticket requests or Diamond ticket forging;
- certificate enrollment/exploitation;
- BloodHound CE archive serialization;
- token impersonation/elevation;
- PRT decryption/extraction;
- functional WinRM-over-WebSocket framing.

See the root [README](../README.md#important-capability-boundaries) for the
operator-facing version of these boundaries.
