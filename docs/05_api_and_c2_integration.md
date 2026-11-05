# Python API and integration

PwnRM's supported integration path is the same one used by the CLI:
`argument_parser()` or an equivalent `Namespace`, `create_transport()`,
`Runspace`, and optionally `PwnShell`.

## Run one command

```python
from pwnrm import Runspace, argument_parser, create_transport

args = argument_parser().parse_args([
    "-d", "CORP", "-u", "operator", "-p", "password", "dc01"
])

with Runspace(create_transport(args), timeout=args.timeout) as runspace:
    errors = []
    for record in runspace.run_command("whoami /all"):
        if "stdout" in record:
            print(record["stdout"], end="")
        elif "error" in record:
            errors.append(record["error"])
    if errors:
        raise RuntimeError("; ".join(errors))
```

`run_command()` is a generator and must be consumed. An idle record is a
scheduling point, not command output.

## Use the shell dispatcher non-interactively

```python
from pwnrm import PwnShell, Runspace, argument_parser, create_transport

args = argument_parser().parse_args([
    "-k", "--ccache", "/tmp/operator.ccache", "dc01"
])

with Runspace(create_transport(args), timeout=30) as runspace:
    shell = PwnShell(runspace, target_info={"host": "dc01", "user": "operator"})
    result = shell.repl(inputs=["whoami", "!sysinfo", "!laps encrypted"])
    if result and result.get("status") in {"error", "failed", "interrupted"}:
        raise RuntimeError(result)
```

For a batch, `repl()` returns the first failure instead of hiding it behind a
later successful command. An interactive call is `shell.repl()` with no
`inputs` argument.

## Construct a transport directly

Credential and transport classes are public configuration containers:

```python
from pwnrm import NTCredential, SPNEGOTransport, Runspace

credential = NTCredential("CORP", "operator", password="password")
transport = SPNEGOTransport("https://dc01:5986/wsman", credential)
transport.session.verify = True

with Runspace(transport, timeout=30) as runspace:
    print("".join(
        event.get("stdout", "")
        for event in runspace.run_command("$PSVersionTable.PSVersion")
    ))
```

`Runspace` delegates authentication and message encryption to pypsrp/pyspnego.
The legacy `Transport.send()` wire helpers are not the recommended integration
surface. `WebSocketTransport.send()` always raises because no WebSocket frame
backend is implemented.

## Session manager

```python
from pathlib import Path
from pwnrm import SessionManager

manager = SessionManager(base_dir=Path("/secure/operator-state"))
manager.register_session(runspace_a, transport_a, {"host": "dc01", "user": "CORP\\op"})
manager.register_session(runspace_b, transport_b, {"host": "srv01", "user": "CORP\\op"})

for session_id, output in manager.fan_out_exec("hostname").items():
    print(session_id, output)
```

Each active session needs its own runspace/transport. Fan-out uses separate
worker threads per active session and preserves error records. `save_state()`
stores metadata only; it does not serialize a reconnectable runspace.

## Local SOCKS5 and port forwarding

```python
from pwnrm import PortForwarder, Socks5Server

socks = Socks5Server("127.0.0.1", 0)
socks.start()
print("SOCKS port:", socks.bind_port)

forwards = PortForwarder()
forward_id = forwards.start_local_forward(
    local_port=0,
    remote_host="127.0.0.1",
    remote_port=8080,
)
print(forwards.list_forwards())

forwards.stop_forward(forward_id)
socks.stop()
```

Port `0` requests a kernel-assigned local port. These classes perform direct
operator-side connections and have no relationship to a `Runspace` object.

## Loot manager

```python
from pathlib import Path
from pwnrm import LootManager

loot = LootManager(base_dir=Path("/secure/operator-state"))
loot.store_artifact("dc01", "dumps", "SYSTEM", system_bytes, "!download")
loot.store_credential("dc01", "NTLM", "CORP\\user", nt_hash, "offline_parse")
print(loot.summary())
```

Callers must choose a protected base directory. Secrets are written to
`credentials.json`; the manifest hashes the secret for integrity/indexing but
does not replace the stored value or encrypt it.

## Modules and plugins

```python
from pwnrm import BaseModule, ModuleManager

class ExampleModule(BaseModule):
    name = "example"
    description = "Example read-only module"

    def run(self, shell, args):
        interrupted = shell.run_with_interrupt("Get-Date", shell.write_line)
        return {"status": "interrupted" if interrupted else "completed"}

manager = ModuleManager()
manager.register(ExampleModule)
```

Module names must match `[a-z][a-z0-9_-]{0,63}`. Duplicate registration cannot
replace a built-in. External plugin files must be regular, owned by the current
UID on POSIX, and not group/world writable. Loading a plugin executes Python
code, so permission checks do not substitute for code review.

## Result contract

Control commands and modules return a dictionary containing `status`. Common
values are `completed`, `listed`, `error`, `failed`, `interrupted`, `help`, and
`closed`. Integrators should treat at least `error`, `failed`, and
`interrupted` as unsuccessful and should also consume all runspace error
records.
