"""
pwnrm.cli — CLI entry point & Dead Reckoning replay dispatcher
"""

import sys
import re
import logging
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from impacket import version
from impacket.examples import logger

from .core       import Runspace, create_transport, argument_parser
from .shell      import PwnShell
from .shell.ui   import _BANNER, c, DIM, Y, G, R, BLD


def _display_host(transport, args) -> str:
    """Return a printable host without ever echoing inline credentials."""
    url = getattr(transport, "url", "")
    if isinstance(url, bytes):
        url = url.decode("utf-8", errors="replace")
    if isinstance(url, str) and url:
        host = urlparse(url).hostname
        if host:
            return host

    target = getattr(args, "target", "")
    if not isinstance(target, str) or not target:
        return "?"
    # Impacket-style targets place the endpoint after the final '@'.  Discard
    # the complete credential portion before parsing the remaining endpoint.
    endpoint = target.rsplit("@", 1)[-1]
    parsed = urlparse(endpoint if "://" in endpoint else f"//{endpoint}")
    return parsed.hostname or "?"


def parse_replay_log(log_path: str) -> list[str]:
    """Extracts executable commands from a PwnRM transcript log."""
    path = Path(log_path)
    if not path.is_file():
        raise FileNotFoundError(f"Replay log not found: {log_path}")
    commands = []
    # Match lines like "PS C:\Users\Admin> whoami" or raw operator inputs
    cmd_re = re.compile(r"^PS\s+[^>]+>\s*(.+)$")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        m = cmd_re.match(line)
        if m:
            cmd = m.group(1).strip()
            if cmd and not cmd.startswith("exit") and not cmd.startswith("quit"):
                commands.append(cmd)
    return commands


def main() -> int:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    print(_BANNER)
    args      = argument_parser().parse_args()
    logger.init(args.ts)
    logging.getLogger().setLevel(logging.DEBUG if args.debug else logging.INFO)
    if args.debug:
        logging.debug(version.getInstallationPath())

    timeout   = args.timeout
    command_failed = False
    try:
        transport = create_transport(args)
    except Exception as e:
        logging.error("Transport setup failed: %s", e)
        return 1

    creds = getattr(transport, "creds", None)
    username = getattr(creds, "username", "") or getattr(args, "username", "") or "?"
    domain = getattr(creds, "domain", "")
    display_user = f"{domain}\\{username}" if domain and username != "?" else username
    # Never reuse the raw target string here: it may contain user:password@host.
    display_host = _display_host(transport, args)
    tinfo = {"host": display_host, "user": display_user}

    try:
        with Runspace(transport, timeout) as runspace:
            shell = PwnShell(runspace, target_info=tinfo)
            try:
                if args.replay:
                    replayed_cmds = parse_replay_log(args.replay)
                    print(c(Y + BLD, f"\n  [⚡] Dead Reckoning Replay: executing {len(replayed_cmds)} commands from {args.replay}...\n"))
                    replay_result = shell.repl(iter(replayed_cmds))
                    replay_failed = (
                        isinstance(replay_result, dict)
                        and replay_result.get("status") in {"error", "failed", "interrupted"}
                    )
                    command_failed = command_failed or replay_failed
                    if replay_failed:
                        print(c(Y + BLD, "\n  [!] Replay finished with at least one failed command. Entering interactive session.\n"))
                    else:
                        print(c(G + BLD, "\n  [+] Replay sequence completed. Entering interactive session.\n"))
                    shell.repl()
                elif args.X:
                    result = shell.repl(iter([args.X]))
                    command_failed = isinstance(result, dict) and result.get("status") in {"error", "failed", "interrupted"}
                else:
                    shell.help()
                    shell.repl()
            except EOFError:
                pass
            finally:
                elapsed = str(datetime.now() - shell.start_time).split(".")[0]
                print(c(DIM, f"\n[~] Session duration: {elapsed}  |  Commands: {shell.cmd_count}\n"))
    except Exception as e:
        logging.error("Connection failed: %s", e)
        return 1
    return 1 if command_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
