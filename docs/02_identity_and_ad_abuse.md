# Identity and Active Directory modules

Every module runs in the authenticated remote PowerShell context. Results are
therefore limited by that identity's directory permissions, local profile
access, network reachability, and PowerShell/.NET capabilities.

## ADCS (`!adcs`)

The ADCS module discovers Enterprise CAs and published certificate templates,
then reports conditions useful for a manual assessment:

- CA name, DNS host, published templates, certificate expiration, and selected
  CA properties when accessible;
- template authentication EKUs, enrollee-supplied subject/SAN flag, approval
  and authorized-signature requirements;
- Certificate Request Agent and Any Purpose prerequisite combinations;
- Enroll/AutoEnroll exposure and broadly controllable template ACLs;
- optional WSUS client policy plus code-signing-template correlation.

Options:

```text
!adcs --quick
!adcs --template User
!adcs --ca Corp-CA
!adcs --wsus
!adcs --alt administrator@corp.local
```

`--alt` annotates matching findings only; it never submits a request. The
module performs prerequisite and ACL triage for common ESC1/ESC2/ESC3-style
conditions. It does not claim complete ESC1–ESC17 validation, test enrollment,
or issue a certificate. A finding must be confirmed against effective group
membership, publication, CA policy, mapping policy, and an authorized request.

## Kerberos (`!kerberos`)

Selectors restrict the LDAP reconnaissance performed:

- `roast`: enabled user accounts with SPNs and advertised encryption types;
- `asrep`: accounts with `DONT_REQ_PREAUTH`;
- `rbcd`: objects carrying
  `msDS-AllowedToActOnBehalfOfOtherIdentity`;
- `dmsa`: Server 2025 delegated managed service account attributes,
  including `msDS-DelegatedManagedServiceAccount`,
  `msDS-DelegatedMSAState`, and
  `msDS-ManagedAccountPrecededByLink`;
- `diamond`: current-domain information and prerequisites needed by separate
  ticket tooling.

The module enumerates candidates. It does not request AS-REPs/TGSs, crack
material, modify delegation, or forge a Diamond ticket.

## Operator ticket manager (`!ticket`)

`!ticket list [CCACHE]` and `!ticket inspect [INDEX] [CCACHE]` parse the local
MIT ccache and show the client/server principal, encryption type, flags, start,
expiry, and renewal time. `!ticket use CCACHE` selects the operator default for
future connections; it does not re-authenticate an already-open backend.
`!ticket renew [CCACHE]` uses `kinit -R` only for a cache containing a TGT and
rejects service-ticket-only S4U caches.

The alias `!tickets` is accepted, but `!ticket` is the documented command. No
subcommand performs ticket injection, service-ticket requests, or forging.

## Windows LAPS (`!laps`)

The module queries computer objects for:

- legacy `ms-Mcs-AdmPwd` and expiration;
- modern `msLAPS-Password`;
- `msLAPS-EncryptedPassword` and encrypted DSRM data;
- password-history entry counts.

`all` includes computers without readable LAPS values. `encrypted` includes
encrypted blob metadata. The module does not decrypt encrypted LAPS data; it
reports only what the current directory identity is authorized to read.

## ACL (`!acl`)

By default, the ACL module checks a fixed set of high-value objects. Use
`--target NAME_OR_DN` for one object or `tier0` for `adminCount=1` objects and
GPO containers. It reports allowed ACEs containing GenericAll, GenericWrite,
WriteDacl, WriteOwner, WriteProperty, or ExtendedRight when the trustee looks
broad or directly relevant.

This is a heuristic review, not an effective-access solver. Inheritance,
deny ACEs, nested group membership, object-specific GUIDs, and owner semantics
still require manual validation.

## Token (`!token`)

`privs` shows the current process token's privileges. `list` maps visible
processes to owners and highlights high-value identities. With no selector,
both inventories run.

The module does not duplicate or impersonate a token and does not change the
session identity. The former `--elevate` claim is explicitly rejected.

## Credential artifacts (`!creds`)

Selectors are independently usable:

- `vault`: Windows Credential Manager/Vault metadata;
- `dpapi`: current-user DPAPI master-key file inventory;
- `history`: recent PowerShell console history;
- `browser`: Chrome, Edge, and Brave credential database locations;
- `decrypt BASE64`: `CryptUnprotectData` as the current remote user;
- `lsa`: use an available in-memory credential executor, with a compact
  minidump/pypykatz fallback;
- `lsa --lsa-executor /path/tool.exe`: select a local x64 executor PE;
- `lsa --lsa-output C:\absolute\path.dmp`: choose the temporary remote path;
- `lsa --download`: additionally retain the raw dump in the local loot store.

DPAPI input is validated and limited to 4 MiB. Native output memory is released
with `LocalFree`, and the temporary managed buffer is cleared. Artifact
inventory does not imply that the underlying secret was decrypted.

LSASS extraction requires an administrator context with the necessary process
access (normally `SeDebugPrivilege`). Protected Process Light and endpoint
controls can still block it. PwnRM automatically uses the operator's
`PWNRM_LSA_EXECUTOR`, a `mimikatz.exe` on `PATH`, or the standard Exegol x64
Mimikatz resource when present. The PE runs through the in-memory
No-Consolation loader and its output is captured; no dump is staged. If no
executor exists, PwnRM creates a selective credential minidump, compresses and
parses it with pypykatz, zeroes its buffers, and verifies remote deletion.
`--download` deliberately selects that dump backend and stores a protected
local raw copy while still deleting the remote copy.

## Entra (`!entra`)

The default mode filters `dsregcmd /status` to device join and PRT status.
`full` additionally checks accessible user profiles for WAM, Azure CLI, MSAL, and
Azure PowerShell cache paths.

The module reports status and paths. It does not decrypt WAM storage or extract
a usable PRT/access token.

## BloodHound-oriented reconnaissance (`!bloodhound`)

Collection method names are `DCOnly`, `User`, `Computer`, `Group`, `Session`,
and `All`; comma-separated combinations are accepted. Output is a compact
operator summary of directory and local-session relationships.

It is not a SharpHound replacement and does not emit a BloodHound CE import
archive. Use a supported collector when importable graph data is required.
