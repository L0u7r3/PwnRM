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
!evasion --edr
!evasion --amsi
!evasion --etw
!evasion --amsi --etw
!amsi
```

With no selector, AMSI and ETW patches are attempted. `--edr` inventories a
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

`!upload -xor` stores bytes transformed by a random per-process key. The remote
loader reverses that transformation in memory:

```text
!upload -xor payload.ps1 C:\Windows\Temp\payload.bin
!psrun -xor C:\Windows\Temp\payload.bin
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

## Reverse shell (`!revshell`)

The reverse shell uses native Winsock/CreateProcess imports in the remote
PowerShell process. Listener input is validated as IPv4 and port 1–65535; IPv6
is rejected explicitly. It is a raw command channel without authentication or
encryption and should only be used on an engagement-controlled network.
