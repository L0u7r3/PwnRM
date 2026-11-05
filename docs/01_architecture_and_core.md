# Architecture and core

## Execution path

```text
CLI arguments
  -> create_transport()
  -> Runspace(pypsrp.WSMan + RunspacePool)
  -> PwnShell command dispatcher
  -> remote PowerShell pipeline or local subsystem
```

`create_transport()` parses the target, validates authentication inputs, and
returns a configuration object. `Runspace` maps that object to pypsrp and owns
the actual WS-Man/PSRP connection. The older low-level SOAP helpers remain for
compatibility and tests, but normal CLI execution always uses pypsrp.

## Transport selection

Selection order is:

1. `--pfx`: HTTPS client certificate; HTTPS/5986 is selected by default.
2. `-k` / `--kerberos`: MIT-compatible ccache consumed by pyspnego.
3. `--credssp`: plaintext username/password delegated through CredSSP.
4. default: SPNEGO/NTLM with password or NT hash.

An NT hash must contain exactly 32 hexadecimal characters. Both `NT` and
`LM:NT` input forms are accepted; only the NT component is passed to pyspnego.

For S4U service-ticket-only caches, PwnRM:

- decodes Impacket's `CountedOctetString` ticket bytes correctly;
- creates a private lowercase-hostname cache copy when MIT Kerberos
  canonicalization requires it;
- derives the service and hostname override from the ticket SPN, allowing
  tickets such as `TERMSRV/DC01` to reach the matching service principal.

Temporary cache and PFX material is created mode `0600` under mode `0700`
directories and registered for process-exit cleanup.

## TLS and HTTP policy

- Certificate verification defaults to enabled.
- `--no-ssl-verify` is the explicit opt-out.
- Redirects are disabled to prevent a WinRM endpoint redirecting credentials or
  traffic to an unintended destination.
- `HTTP_PROXY`, `HTTPS_PROXY`, and related environment state is ignored.
- Client certificate auth is not silently attempted over plaintext HTTP.

## Runspace lifecycle and output

`Runspace` opens one `RunspacePool` and creates an asynchronous `PowerShell`
pipeline for each command. It polls with short operation timeouts so `Ctrl+C`
can call `PowerShell.stop()` without making concurrent encrypted WS-Man
requests.

Records are normalized into dictionaries:

```python
{"stdout": "..."}
{"error": "..."}
{"warn": "..."}
{"verbose": "..."}
{"info": "...", "endl": "\n"}
{"progress": "..."}
{"idle": True}
```

Remote error records are retained by `PwnShell`. A module that returns
`completed` while its pipeline emitted an error is normalized to an `error`
result. `pwnrm -X` exits nonzero for error, failed, or interrupted results.

## Command dispatcher

Built-ins match the complete first token: `!adcsfoo` cannot invoke `!adcs`.
Module and control commands validate option counts instead of silently ignoring
extra arguments. Batch/replay execution preserves the first failure even if a
later command succeeds.

`run_sync()` has a 1 MiB UTF-8 output limit and interrupts over-limit output.
Streaming commands pass each record to a callback while preserving remote error
records.

## Sessions

`SessionManager` registers runspace nodes and supports:

- list and switch;
- concurrent `exec-all` using a bounded thread pool;
- output labels of the form `[S:id | host]`;
- an encrypted metadata snapshot readable only within the same process.

Session snapshots are not reconnectable credentials and are intentionally not
portable across process restarts. State filenames reject separators and
traversal. Files are atomically written mode `0600`, and symlink destinations
are refused.

## Direct local networking

`Socks5Server` implements RFC 1928 NO-AUTH CONNECT for IPv4, IPv6, and domain
destinations. `PortForwarder` implements a direct local TCP listener and
bidirectional relay. Both originate their outbound connection on the operator
machine.

They are useful for local routing convenience but are not remote pivots and do
not send socket data through WinRM or PSRP. End-to-end tests connect each
implementation to a real local echo server and verify data in both directions.

## WebSocket compatibility class

`WebSocketTransport` remains importable so existing code fails predictably, but
PwnRM does not implement WebSocket framing or a pypsrp WebSocket backend. Its
`send()` method raises `TransportError` with the supported alternatives.
