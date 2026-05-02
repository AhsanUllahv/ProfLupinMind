import asyncio
import os
import pty
import re
import select
import signal
import time
from dataclasses import dataclass
from typing import Callable, Optional

_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Prepend Go/local tool paths so ProjectDiscovery tools (httpx, nuclei, subfinder, etc.)
# take precedence over Python shims that share the same binary name.
_TOOL_PATHS = [
    "/home/kali/go/bin",
    "/usr/local/bin",
    "/usr/local/go/bin",
]
_current_path = os.environ.get("PATH", "")
_extra = ":".join(p for p in _TOOL_PATHS if p not in _current_path)
_ENV = {**os.environ, "PATH": f"{_extra}:{_current_path}" if _extra else _current_path}


@dataclass
class ExecutionResult:
    command: str
    output: str
    exit_code: int
    duration: float
    timed_out: bool = False


async def _kill_process_group(process: asyncio.subprocess.Process) -> None:
    """Kill a subprocess shell and any scanner process it spawned."""
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except ProcessLookupError:
        return
    except Exception:
        process.kill()
    await process.wait()


async def pty_execute(
    command: str,
    on_line: Optional[Callable[[str], None]] = None,
    on_start: Optional[Callable[[int], None]] = None,
    on_finish: Optional[Callable[[int, int], None]] = None,
    timeout: int = 300,
) -> ExecutionResult:
    """Run a command inside a pseudo-terminal so interactive tools (wifite, etc.) work."""
    start = time.time()
    output_lines: list[str] = []
    timed_out = False

    master_fd, slave_fd = pty.openpty()

    process = await asyncio.create_subprocess_shell(
        command,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        start_new_session=True,
        env=_ENV,
    )
    os.close(slave_fd)

    if on_start:
        on_start(process.pid)

    os.set_blocking(master_fd, False)
    buf = b""
    deadline = start + timeout

    def _emit_complete_lines() -> None:
        nonlocal buf
        while b"\n" in buf:
            raw_line, buf = buf.split(b"\n", 1)
            line = _ANSI_ESCAPE.sub("", raw_line.decode("utf-8", errors="replace")).rstrip()
            if line.strip():
                output_lines.append(line)
                if on_line:
                    on_line(line)

    async def _drain_available() -> bool:
        nonlocal buf
        saw_data = False
        while True:
            try:
                ready, _, _ = select.select([master_fd], [], [], 0)
                if not ready:
                    break
                chunk = os.read(master_fd, 4096)
                if not chunk:
                    break
                saw_data = True
                buf += chunk.replace(b"\r", b"\n")
                _emit_complete_lines()
            except BlockingIOError:
                break
            except OSError:
                break
        return saw_data

    while True:
        await _drain_available()
        if process.returncode is not None:
            break
        if time.time() >= deadline:
            await _kill_process_group(process)
            timed_out = True
            msg = f"[TIMEOUT] Command killed after {timeout}s"
            output_lines.append(msg)
            if on_line:
                on_line(msg)
            break
        try:
            await asyncio.wait_for(process.wait(), timeout=0.05)
        except asyncio.TimeoutError:
            pass

    await _drain_available()
    if buf.strip():
        line = _ANSI_ESCAPE.sub("", buf.decode("utf-8", errors="replace")).rstrip()
        if line.strip():
            output_lines.append(line)
            if on_line:
                on_line(line)

    try:
        if process.returncode is None:
            await asyncio.wait_for(process.wait(), timeout=0.2)
    except asyncio.TimeoutError:
        await _kill_process_group(process)
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass

    exit_code = process.returncode if process.returncode is not None else -1
    if on_finish:
        on_finish(process.pid, exit_code)

    return ExecutionResult(
        command=command,
        output="\n".join(output_lines),
        exit_code=exit_code,
        duration=time.time() - start,
        timed_out=timed_out,
    )


async def execute(
    command: str,
    on_line: Optional[Callable[[str], None]] = None,
    on_start: Optional[Callable[[int], None]] = None,
    on_finish: Optional[Callable[[int, int], None]] = None,
    timeout: int = 300,
) -> ExecutionResult:
    """
    Run a shell command, stream each output line via on_line callback,
    and return the full result when done.
    stderr is merged into stdout so all output is captured together.
    """
    start = time.time()
    output_lines: list[str] = []
    timed_out = False

    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        start_new_session=True,
        env=_ENV,
    )
    if on_start:
        on_start(process.pid)

    async def _read():
        async for raw in process.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip()
            output_lines.append(line)
            if on_line:
                on_line(line)

    try:
        await asyncio.wait_for(
            asyncio.gather(_read(), process.wait()),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        await _kill_process_group(process)
        timed_out = True
        msg = f"[TIMEOUT] Command killed after {timeout}s"
        output_lines.append(msg)
        if on_line:
            on_line(msg)

    exit_code = process.returncode if process.returncode is not None else -1
    if on_finish:
        on_finish(process.pid, exit_code)

    return ExecutionResult(
        command=command,
        output="\n".join(output_lines),
        exit_code=exit_code,
        duration=time.time() - start,
        timed_out=timed_out,
    )
