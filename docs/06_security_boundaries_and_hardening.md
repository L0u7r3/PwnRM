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

An imported plugin is arbitrary Python. `!psrun`, `!netrun`, raw PowerShell,
and playbooks can execute arbitrary authorized code. Ownership/permission and
schema checks reduce unintended loading; they do not sandbox execution.

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
is attempted in `finally`; staged files remain until operator cleanup.

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
