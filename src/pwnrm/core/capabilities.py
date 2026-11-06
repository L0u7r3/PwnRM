"""Truthful per-command backend, privilege, artifact, and risk metadata."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CommandCapability:
    command: str
    backends: str
    privilege: str
    artifacts: str
    risk: str
    note: str

    def available(self, *, persistent: bool) -> bool:
        return self.backends != "winrm" or persistent


def _cap(
    command: str,
    backends: str = "all",
    privilege: str = "current user",
    artifacts: str = "none",
    risk: str = "low",
    note: str = "",
) -> CommandCapability:
    return CommandCapability(command, backends, privilege, artifacts, risk, note)


COMMAND_CAPABILITIES = {
    "session": _cap("session", artifacts="local session metadata", note="Session control is local to this PwnRM process."),
    "socks": _cap("socks", backends="local", artifacts="local listener", risk="medium", note="Connections originate from the operator host."),
    "portfwd": _cap("portfwd", backends="local", artifacts="local listener", risk="medium", note="Direct operator-side TCP forwarding."),
    "ligolo": _cap("ligolo", backends="winrm", artifacts="detached target process", risk="high", note="Requires a persistent WinRM runspace for in-memory staging."),
    "jobs": _cap("jobs", artifacts="local mode-0600 registry", risk="medium", note="Controls only jobs created and tracked by PwnRM."),
    "ticket": _cap("ticket", backends="local", privilege="operator", artifacts="none", note="Inspects local ccaches; use/renew never injects a ticket remotely."),
    "capabilities": _cap("capabilities", backends="local", privilege="operator", note="Availability reflects the active backend."),
    "module": _cap("module", artifacts="module dependent", risk="medium", note="Requirements depend on the selected module."),
    "loot": _cap("loot", backends="local", privilege="operator", artifacts="reads local loot index"),
    "opsec": _cap("opsec", backends="local", privilege="operator", artifacts="none", note="Changes local jitter and command rewriting policy."),
    "playbook": _cap("playbook", artifacts="playbook dependent", risk="high", note="Runs a sequence of PwnRM commands."),
    "help": _cap("help", backends="local", privilege="operator"),
    "adcs": _cap("adcs", artifacts="none", risk="medium", note="Read-only CA, template, ACL, and WSUS triage."),
    "kerberos": _cap("kerberos", artifacts="none", risk="medium", note="Reconnaissance only; does not forge or inject tickets."),
    "entra": _cap("entra", artifacts="none", note="Reads join state and accessible cache paths."),
    "creds": _cap("creds", privilege="mode dependent; LSASS requires admin", artifacts="optional transient dump", risk="high", note="LSASS mode requires WinRM for in-memory execution."),
    "laps": _cap("laps", privilege="directory read rights", artifacts="none", risk="medium"),
    "acl": _cap("acl", privilege="directory read rights", artifacts="none", risk="medium"),
    "token": _cap("token", artifacts="none", note="Inventory only; no token elevation."),
    "bloodhound": _cap("bloodhound", privilege="directory read rights", artifacts="none", risk="medium", note="Summary output, not an import archive."),
    "lateral": _cap("lateral", artifacts="network connections", risk="high", note="Performs a bounded network probe."),
    "vss": _cap("vss", privilege="local administrator", artifacts="ephemeral shadow copy and staging", risk="high", note="Remote staging is removed and verified unless --download is selected."),
    "coerce": _cap("coerce", artifacts="outbound network authentication", risk="high", note="Triggers explicit WebDAV/SMB UNC probes."),
    "evasion": _cap("evasion", backends="winrm", artifacts="process memory changes", risk="high", note="AMSI/ETW changes are process-scoped."),
    "adtriage": _cap("adtriage", artifacts="none"),
    "shares": _cap("shares", artifacts="SMB connections", risk="medium"),
    "sessions": _cap("sessions", artifacts="none"),
    "sysinfo": _cap("sysinfo", artifacts="none"),
    "download": _cap("download", artifacts="local file", risk="medium"),
    "upload": _cap("upload", artifacts="remote file", risk="high"),
    "amsi": _cap("amsi", backends="winrm", artifacts="process memory changes", risk="high"),
    "psrun": _cap("psrun", artifacts="network retrieval; process memory", risk="high"),
    "netrun": _cap("netrun", artifacts="network retrieval; process memory", risk="high"),
    "noconsolation": _cap("noconsolation", backends="winrm", artifacts="process memory; optional detached process", risk="high", note="Output capture is opt-in; detached jobs survive RunspacePool closure."),
    "revshell": _cap("revshell", artifacts="outbound TCP connection", risk="high"),
    "log": _cap("log", backends="local", privilege="operator", artifacts="local transcript", risk="medium"),
    "stoplog": _cap("stoplog", backends="local", privilege="operator", artifacts="local transcript", risk="low"),
    "exit": _cap("exit", backends="local", privilege="operator", note="Does not automatically stop detached jobs."),
}


def normalize_command_name(value: str) -> str:
    return value.strip().lower().lstrip("!").split(None, 1)[0]


def get_capability(value: str) -> CommandCapability:
    name = normalize_command_name(value)
    try:
        return COMMAND_CAPABILITIES[name]
    except KeyError as exc:
        raise KeyError(f"unknown command: {value}") from exc
