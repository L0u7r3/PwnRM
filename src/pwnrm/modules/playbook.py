"""
modules.playbook — Declarative Playbook & Automation Workflow Engine
Runs structured operation workflows with conditional branching (when), variable capture, and automated on_fail cleanup handlers.
"""

import json
import re
from io import StringIO
from pathlib import Path
from typing import List, Any, Dict, Union
from . import BaseModule
from ..shell.ui import c, R, G, Y, B, M, C, DIM, BLD, RST


class PlaybookModule(BaseModule):
    name = "playbook"
    description = "Declarative Automation Engine (Conditional branching, on_fail cleanup, output capture)"
    author = "uziii2208"
    options = {
        "--file": {"desc": "Path to playbook JSON file with conditional branching & cleanup hooks"},
        "--list": {"desc": "List built-in operation playbooks"},
        "--run": {"desc": "Run built-in playbook: default_triage, ad_recon, stealth_audit, smart_triage"},
    }

    BUILTIN_PLAYBOOKS = {
        "default_triage": [
            {"cmd": "!evasion"},
            {"cmd": "!sysinfo"},
            {"cmd": "!sessions -q"},
            {"cmd": "!shares -q"},
            {"cmd": "!creds"},
        ],
        "ad_recon": [
            {"cmd": "!evasion"},
            {"cmd": "!adtriage -q", "capture_as": "triage"},
            {"cmd": "!adcs", "when": "triage contains 'ADCS'"},
            {"cmd": "!kerberos", "when": "triage contains 'SPN'"},
            {"cmd": "!bloodhound"},
        ],
        "smart_triage": [
            {"cmd": "!evasion"},
            {"cmd": "!sysinfo", "capture_as": "sysinfo"},
            {"cmd": "!adtriage -q", "capture_as": "triage"},
            {"cmd": "!adcs", "when": "triage contains 'Certificate'"},
            {"cmd": "!kerberos", "when": "triage contains 'SPN'"},
            {"cmd": "!creds"},
        ],
        "stealth_audit": [
            {"cmd": "!evasion"},
            {"cmd": "!sysinfo"},
            {"cmd": "!entra"},
            {"cmd": "!creds"},
        ]
    }

    @staticmethod
    def _evaluate_condition(when: str, context: Dict[str, str], last_output: str) -> bool:
        """Evaluates simple conditional DSL: '<var> contains <substring>' or direct regex."""
        if not when:
            return True
        m = re.match(r"^(\w+)\s+contains\s+['\"]?([^'\"]+)['\"]?$", when.strip(), re.IGNORECASE)
        if m:
            var_name, expected = m.group(1), m.group(2)
            source_text = context.get(var_name, last_output if var_name in ("output", "last_output") else "")
            return expected.lower() in source_text.lower()
        # Direct substring in last_output
        return when.lower() in last_output.lower()

    @staticmethod
    def _validate_steps(raw_steps: Any) -> List[Union[str, Dict[str, Any]]]:
        """Validate the deliberately small playbook schema before execution."""
        if isinstance(raw_steps, dict):
            raw_steps = raw_steps.get("steps")
        if not isinstance(raw_steps, list) or not raw_steps:
            raise ValueError("playbook must contain a non-empty steps array")

        allowed = {"cmd", "when", "capture_as", "on_fail", "cleanup_on_fail"}
        validated = []
        for index, step in enumerate(raw_steps, 1):
            if isinstance(step, str):
                if not step.strip():
                    raise ValueError(f"step {index} has an empty command")
                validated.append(step)
                continue
            if not isinstance(step, dict):
                raise ValueError(f"step {index} must be a command string or object")
            unknown = set(step) - allowed
            if unknown:
                raise ValueError(f"step {index} has unknown fields: {', '.join(sorted(unknown))}")
            if not isinstance(step.get("cmd"), str) or not step["cmd"].strip():
                raise ValueError(f"step {index} has an invalid command")
            for field in ("when", "capture_as"):
                if field in step and not isinstance(step[field], str):
                    raise ValueError(f"step {index} field '{field}' must be a string")
            cleanup = step.get("cleanup_on_fail")
            if cleanup is not None:
                if isinstance(cleanup, str):
                    cleanup = [cleanup]
                if (
                    not isinstance(cleanup, list)
                    or not cleanup
                    or any(not isinstance(cmd, str) or not cmd.strip() for cmd in cleanup)
                ):
                    raise ValueError(
                        f"step {index} field 'cleanup_on_fail' must be a command or non-empty command array"
                    )
                step = dict(step)
                step["cleanup_on_fail"] = cleanup
            capture_as = step.get("capture_as")
            if capture_as and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", capture_as):
                raise ValueError(f"step {index} has an invalid capture_as name")
            if step.get("on_fail", "abort") not in {"abort", "continue"}:
                raise ValueError(f"step {index} on_fail must be 'abort' or 'continue'")
            validated.append(step)
        return validated

    def run(self, shell, args: List[str]) -> Any:
        if not args or args == ["--list"]:
            shell.write_info(c(C + BLD, "  [*] Built-in Playbooks:"))
            for name, steps in self.BUILTIN_PLAYBOOKS.items():
                shell.write_info(f"    - {c(Y, name)} ({len(steps)} steps)")
                for s in steps:
                    cmd_str = s if isinstance(s, str) else s.get("cmd", "")
                    when_str = f" [when: {s.get('when')}]" if isinstance(s, dict) and s.get("when") else ""
                    shell.write_info(f"        -> {cmd_str}{when_str}")
            return {"status": "listed"}

        pb_name = ""
        pb_file = ""
        if len(args) == 2 and args[0] == "--run":
            pb_name = args[1]
        elif len(args) == 2 and args[0] == "--file":
            pb_file = args[1]
        elif len(args) == 1 and args[0] in self.BUILTIN_PLAYBOOKS:
            pb_name = args[0]
        else:
            shell.write_warning("Unknown playbook or syntax. Use !playbook --list")
            return {"status": "error", "error": "invalid syntax"}

        steps = []
        if pb_file:
            try:
                playbook_path = Path(pb_file)
                if not playbook_path.is_file() or playbook_path.is_symlink():
                    raise ValueError("playbook path must be a regular non-symlink file")
                if playbook_path.stat().st_size > 1024 * 1024:
                    raise ValueError("playbook exceeds the 1 MiB size limit")
                with open(playbook_path, "r", encoding="utf-8") as f:
                    steps = self._validate_steps(json.load(f))
                pb_name = playbook_path.stem
            except Exception as e:
                shell.write_error(f"Failed to load playbook file {pb_file}: {e}")
                return {"status": "error"}
        elif pb_name in self.BUILTIN_PLAYBOOKS:
            steps = self._validate_steps(self.BUILTIN_PLAYBOOKS[pb_name])

        if steps:
            shell.write_info(c(M + BLD, f"  [*] Executing Playbook: '{pb_name}' ({len(steps)} steps)"))
            cleanup_stack = []
            context: Dict[str, str] = {}
            last_output = ""

            for idx, step in enumerate(steps, 1):
                cmd_str = step if isinstance(step, str) else step.get("cmd", "")
                when_cond = step.get("when") if isinstance(step, dict) else None
                capture_var = step.get("capture_as") if isinstance(step, dict) else None
                on_fail = step.get("on_fail", "abort") if isinstance(step, dict) else "abort"
                cleanup_cmd = step.get("cleanup_on_fail") if isinstance(step, dict) else None

                if when_cond and not self._evaluate_condition(when_cond, context, last_output):
                    shell.write_info(c(DIM, f"  [-] [Step {idx}/{len(steps)}] Skipped: condition '{when_cond}' was not met."))
                    continue

                if cleanup_cmd:
                    cleanup_stack.extend(cleanup_cmd)

                shell.write_info(c(Y + BLD, f"\n  ==> [Step {idx}/{len(steps)}] Executing: {cmd_str}"))

                # Capture output for conditional evaluation
                captured_lines = []
                orig_write_line = shell.write_line

                def capturing_writer(out):
                    if "stdout" in out:
                        captured_lines.append(out["stdout"])
                    orig_write_line(out)

                failure = None
                result = None
                try:
                    shell.write_line = capturing_writer
                    result = shell.repl(inputs=[cmd_str])
                except Exception as e:
                    failure = str(e)
                finally:
                    shell.write_line = orig_write_line

                if isinstance(result, dict) and result.get("status") in {"error", "failed", "interrupted"}:
                    failure = result.get("error") or result.get("status")

                if failure:
                    shell.write_error(f"  [!] Step {idx} failed: {failure}")
                    if cleanup_stack:
                        shell.write_warning(f"  [*] Executing {len(cleanup_stack)} on_fail cleanup tasks...")
                        for clean in reversed(cleanup_stack):
                            try:
                                shell.repl(inputs=[clean])
                            except Exception as c_err:
                                shell.write_error(f"Cleanup error: {c_err}")
                        cleanup_stack.clear()
                    if on_fail == "continue":
                        shell.write_warning("  [*] Continuing playbook execution (on_fail: continue)...")
                        continue
                    return {"status": "failed", "step": idx}

                last_output = "\n".join(captured_lines)
                if capture_var:
                    context[capture_var] = last_output

            shell.write_info(c(G + BLD, f"\n  [+] Playbook '{pb_name}' completed successfully."))
            return {"status": "completed", "playbook": pb_name}

        shell.write_warning("Unknown playbook or syntax. Use !playbook --list")
        return {"status": "error"}
