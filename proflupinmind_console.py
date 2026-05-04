#!/usr/bin/env python3
"""ProfLupinMind live console — streams structured JSONL events in real time.

Two modes:
  default : follow proflupinmind.events.jsonl and render each event as a banner
  --raw   : legacy tail -f on the plain-text proflupinmind.raw.log
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import select
import subprocess
import sys
import termios
import time
from pathlib import Path

from mcp_server import PROJECT_ROOT, EVENTS_LOG, RAW_OUTPUT_LOG, ProfLupinMindVisualEngine


_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_ESCAPED_PUNCT_RE = re.compile(r'\\([.\+\-\(\)\[\]\{\}"\'])')
_SIMPLE_ESCAPES = {
    r"\r\n": "\n",
    r"\n": "\n",
    r"\r": "\n",
    r"\t": "\t",
}


def _humanize_stdout(text: str) -> str:
    """Render tool output as readable text for the live console."""
    if not text:
        return text

    for src, dst in _SIMPLE_ESCAPES.items():
        text = text.replace(src, dst)

    def _hex_to_char(match: re.Match[str]) -> str:
        try:
            return bytes.fromhex(match.group(1)).decode("latin-1")
        except Exception:
            return match.group(0)

    text = _HEX_ESCAPE_RE.sub(_hex_to_char, text)
    return _ESCAPED_PUNCT_RE.sub(r"\1", text)


def _console_card(mode: str, log_path: Path) -> str:
    C = ProfLupinMindVisualEngine.C
    R = C["RESET"]
    B = C["BOLD"]
    BDR = C["ELECTRIC_BLUE"]
    G = C["MATRIX_GREEN"]
    A = C["NEON_CYAN"]
    W = C["BRIGHT_WHITE"]
    GR = C["TERMINAL_GRAY"]

    def row(label: str, value: str, lc=A, vc=W) -> str:
        return f"{BDR}║  {lc}{label:<14}{R}{vc}{value}{R}\n"

    return (
        f"\n{BDR}╔══════════════════════════════════════════════════════════╗{R}\n"
        f"{BDR}║  {B}{G}  PROFLUPINMIND CONSOLE — LIVE EVENT VIEWER{R}{BDR}               ║{R}\n"
        f"{BDR}╠══════════════════════════════════════════════════════════╣{R}\n"
        + row("Client", "Claude Code in VS Code")
        + row("Transport", "stdio")
        + row("Mode", mode)
        + row("Log", str(log_path))
        + f"{BDR}╚══════════════════════════════════════════════════════════╝{R}\n"
        f"{GR}  Press Ctrl-C to close this viewer. Keyboard input is ignored.{R}\n"
    )


@contextlib.contextmanager
def _viewer_input_guard():
    """Disable local echo/canonical input so accidental typing doesn't clutter output."""
    if not sys.stdin.isatty():
        yield
        return

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    new = termios.tcgetattr(fd)
    new[3] &= ~(termios.ECHO | termios.ICANON)
    new[6][termios.VMIN] = 0
    new[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, new)
    try:
        yield
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, old)


def _drain_stdin() -> None:
    """Discard pending keyboard bytes so they never leak back into shell input."""
    if not sys.stdin.isatty():
        return
    fd = sys.stdin.fileno()
    try:
        while True:
            ready, _, _ = select.select([fd], [], [], 0)
            if not ready:
                break
            data = os.read(fd, 1024)
            if not data:
                break
    except Exception:
        return


def _render_event(event: dict) -> str | None:
    C = ProfLupinMindVisualEngine.C
    R  = C["RESET"]
    CY = C["NEON_CYAN"]
    BL = "\033[94m"
    SOFT = "\033[38;5;252m"

    typ = event.get("type")

    if typ == "command_started":
        cmd = event.get("command", "")
        cmd_name, _, cmd_rest = cmd.partition(" ")
        return (
            f"\n{CY}┌──({BL}kali@kali{CY})-[~]{R}\n"
            f"{CY}└─{BL}$ {BL}{cmd_name}{R}{SOFT} {cmd_rest}{R}\n"
        )

    if typ == "stdout_chunk":
        return f"{SOFT}{event.get('data', '')}{R}"

    if typ == "stdout":
        data = event.get("data", "")
        text = _humanize_stdout(data)
        if not text.endswith("\n"):
            text += "\n"
        return f"{R}{text}"

    if typ == "exit":
        code = event.get("exit_code", -1)
        _ = code
        return (
            f"\n{CY}┌──({BL}kali@kali{CY})-[~]{R}\n"
            f"{CY}└─{BL}$ {R}"
        )

    return None


def follow_jsonl(log_path: Path, start_lines: int) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=True)

    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()
        skip = max(0, len(all_lines) - start_lines)
        for raw in all_lines[skip:]:
            raw = raw.strip()
            if not raw:
                continue
            try:
                rendered = _render_event(json.loads(raw))
                if rendered is not None:
                    print(rendered, end="", flush=True)
            except json.JSONDecodeError:
                print(raw, flush=True)

        try:
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.05)
                    _drain_stdin()
                    continue
                line = line.strip()
                if not line:
                    _drain_stdin()
                    continue
                try:
                    rendered = _render_event(json.loads(line))
                    if rendered is not None:
                        print(rendered, end="", flush=True)
                except json.JSONDecodeError:
                    print(line, flush=True)
                _drain_stdin()
        except KeyboardInterrupt:
            print("\nViewer closed.")
            return 0
    return 0


def follow_raw(log_path: Path, start_lines: int) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.touch(exist_ok=True)
    try:
        proc = subprocess.Popen(["tail", "-n", str(start_lines), "-f", str(log_path)])
        return proc.wait()
    except KeyboardInterrupt:
        print("\nViewer closed.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch ProfLupinMind live tool output")
    parser.add_argument("--raw", action="store_true",
                        help="Legacy mode: tail the plain-text raw log instead of JSONL events")
    parser.add_argument("--log", default="",
                        help="Override the log file path")
    parser.add_argument("-n", "--lines", type=int, default=40,
                        help="Number of existing log entries to show before following")
    parser.add_argument("--no-clear", action="store_true",
                        help="Do not clear the terminal before drawing the console")
    args = parser.parse_args()

    if args.raw:
        log_path = Path(args.log).expanduser() if args.log else RAW_OUTPUT_LOG
        mode = "raw text log"
    else:
        log_path = Path(args.log).expanduser() if args.log else EVENTS_LOG
        mode = "JSONL events"

    if not log_path.is_absolute():
        log_path = PROJECT_ROOT / log_path

    if not args.no_clear:
        print("\033[2J\033[H", end="")
    print(ProfLupinMindVisualEngine.banner())
    print(_console_card(mode, log_path))
    sys.stdout.flush()

    with _viewer_input_guard():
        if args.raw:
            return follow_raw(log_path, args.lines)
        return follow_jsonl(log_path, args.lines)


if __name__ == "__main__":
    raise SystemExit(main())
