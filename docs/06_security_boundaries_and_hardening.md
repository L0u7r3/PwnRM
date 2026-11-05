# Security boundaries and validation

PwnRM handles credentials, executable code, remote output, and collected
artifacts. Its safeguards reduce accidental exposure and obvious injection
paths; they do not turn an untrusted endpoint, plugin, script, assembly, or
playbook into trusted code.

## Trust boundaries

### Operator inputs

CLI values, paths, module options, listener addresses, subnet/port lists, and
playbook files are validated before interpolation or execution. Where a free
string must reach PowerShell/LDAP, PwnRM uses Base64 decoding or dedicated
PowerShell/LDAP escaping.

### Remote endpoint

A WinRM endpoint controls output records and may be malicious. Terminal output
passes through an ANSI/control-sequence sanitizer. Synchronous collection is
bounded, downloads have a maximum size and integrity trailer, and server-returned
paths are validated before reuse.

TLS server validation is enabled by default, but plaintext HTTP still relies on
the selected WS-Man message-encryption/authentication behavior. Use HTTPS when
the Rules of Engagement require transport-layer confidentiality and server
authentication.

### Local filesystem

PwnRM directories are mode `0700` and sensitive files mode `0600` on POSIX.
Loot and session-state writers use random same-directory temporary files plus
`os.replace`, reject symlink targets/directories, and use `O_NOFOLLOW` where
available. Downloads reject symlink destinations.

Filesystem permissions do not provide encryption at rest. Root, the operator
account, backups, endpoint monitoring, or a compromised kernel can still read
the data.

### Dynamic plugins and payloads

An imported plugin is arbitrary Python. `!psrun`, `!netrun`,
`!noconsolation`, raw PowerShell, and playbooks can execute arbitrary authorized
code. Ownership/permission and schema checks reduce unintended loading; they
do not sandbox execution.

No-Consolation integration pins both third-party revisions and their SHA-256
digests. The verified files are fetched by the operator process or read from an
explicit `PWNRM_NOCONSOLATION_ASSET_DIR`; they are not bundled silently and the
target is not asked to retrieve them. A valid digest proves identity with the
pinned artifact, not that arbitrary executable code is safe.

## Authentication material

- PFX private keys and normalized ccaches are placed in private temporary
  directories and removed at process exit.
- Passwords and hashes are not written to debug logs by transport setup.
- Command history excludes common password/hash/ticket/DPAPI keywords, but this
  regex is defense in depth and cannot identify every secret-bearing command.
- CredSSP delegates plaintext credentials by design. Use it only when delegation
  is necessary and authorized.

The supplied ccache, PFX, password, or hash remains the operator's responsibility
before and after PwnRM runs.

## Native runtime changes

AMSI/ETW patching changes executable memory in the remote PowerShell process.
It validates native addresses and protection transitions but cannot guarantee
compatibility with every OS build, security product, or process architecture.
It should be treated as a potentially disruptive action in the Rules of
Engagement.

VSS extraction creates a shadow copy and remote staged files. Shadow deletion
is attempted in `finally`; PwnRM then streams the required hives, parses them
locally, and verifies immediate removal of the remote staging directory. Raw
local retention requires the explicit `--download` option.

LSASS dump staging launches the built-in `comsvcs.dll` minidump entry point,
creates a sensitive remote file, and may be blocked by PPL or endpoint controls.
Failed/partial output is removed, but a successful dump intentionally remains
until PwnRM streams it for parsing and verifies its immediate deletion. Raw
local retention requires the explicit `--download` option.

No-Consolation executes a native PE loader inside a PowerShell process. An
invalid payload, missing dependency, or loader incompatibility can terminate
the remote WinRM provider. Default background jobs are owned by the current
runspace; closing the PwnRM session tears down that execution context. The
explicit `--detached` mode instead creates a WMI-owned PowerShell process and
hands it bytes over a random named pipe. It survives RunspacePool closure and
must be stopped by PID; this is process independence, not reboot persistence.
The process creation, encoded bootstrap command line, named-pipe traffic, and
network activity remain visible to endpoint telemetry.

`!ligolo` is a thin detached-launch alias and does not establish trust in a
third-party agent binary. PwnRM neither pins nor downloads Ligolo-ng on the
operator's behalf; the operator is responsible for source, build provenance,
proxy configuration, certificates, and routes.

## Network side effects

- `!lateral` opens outbound TCP connections from the remote host to the selected
  subnet and may send WS-Management requests.
- `!coerce` attempts UNC access and may emit NetNTLM authentication to the
  operator-controlled listener.
- `!socks` and `!portfwd` listen locally and connect from the operator host.
- `!revshell` creates an unauthenticated raw outbound command channel.

These actions can trigger monitoring and must remain inside the approved scope.

## Validation commands

Run the complete local gate from the repository root:

```bash
python -m pytest -q
python -m pip check
python -m build
python -m twine check dist/*
git diff --check
```

The repository CI additionally runs the custom audit scripts under
`.github/scripts`, dependency auditing, and the supported Python version
matrix. Test counts are intentionally not hard-coded in documentation because
they change as regressions are added.

Generated PowerShell should also be parsed by Windows PowerShell 5.1 and the
remote module matrix should be exercised against a disposable, authorized lab
before a release. Tests should confirm observable output and cleanup, not only
that a command was dispatched.

## Known non-features

The implementation deliberately fails or reports a boundary instead of
pretending success for:

- WebSocket WinRM framing;
- PSRP-carried SOCKS/port forwarding;
- MS-RPRN/MS-EFSR/MS-DFSNM RPC coercion;
- automatic ticket requests/forging;
- certificate exploitation/enrollment;
- BloodHound CE archive generation;
- token impersonation;
- PRT extraction.

Adding any of these requires a real implementation, protocol-level tests, live
lab validation, failure propagation, cleanup behavior, and documentation of
its security side effects.
