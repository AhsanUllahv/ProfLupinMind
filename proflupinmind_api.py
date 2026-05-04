#!/usr/bin/env python3
"""ProfLupinMind Flask API Server — Tool Execution Backend

Runs every subprocess with live stdout output visible in the terminal.
The MCP layer (mcp_server.py) forwards tool calls here via HTTP so that
uvicorn never intercepts the subprocess output.

Usage (standalone):
    python3 proflupinmind_api.py
Or imported and started in a thread by mcp_server.py automatically.
"""
import logging
import hmac
import os
import pty
import re
import signal
import subprocess
import sys
import threading
import time
from flask import Flask, jsonify, request

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ProfLupinMind-API] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def _terminal_write(text: str) -> None:
    """Write directly to the terminal, bypassing transport capture."""
    try:
        with open("/dev/tty", "w", encoding="utf-8", errors="replace") as tty:
            tty.write(text)
            tty.flush()
            return
    except Exception:
        pass
    try:
        # Fall back to stderr — never stdout, which may be the MCP JSON channel.
        sys.stderr.write(text)
        sys.stderr.flush()
    except Exception:
        pass


def _terminal_print(text: str = "") -> None:
    _terminal_write(f"{text}\n")


# ============================================================================
# TERMINAL VISUAL ENGINE
# Self-contained ANSI banner/card printer — command output is written directly
# to the controlling terminal when possible, outside uvicorn/MCP capture.
# ============================================================================

_C = {
    'GREEN':  '\033[38;5;46m',
    'CYAN':   '\033[38;5;51m',
    'BLUE':   '\033[38;5;33m',
    'YELLOW': '\033[38;5;226m',
    'RED':    '\033[38;5;196m',
    'GRAY':   '\033[38;5;240m',
    'WHITE':  '\033[97m',
    'ORANGE': '\033[38;5;208m',
    'RESET':  '\033[0m',
    'BOLD':   '\033[1m',
}


def _print_start_banner(command: str, timeout: int) -> None:
    C = _C
    short = (command[:72] + "…") if len(command) > 75 else command
    _terminal_print(
        f"\n{C['BLUE']}╔══════════════════════════════════════════════════════════════════════════╗{C['RESET']}\n"
        f"{C['BLUE']}║{C['RESET']}  {C['BOLD']}{C['CYAN']}⚡ EXECUTING{C['RESET']}"
        f"  {C['GRAY']}timeout={timeout}s{C['RESET']}\n"
        f"{C['BLUE']}║{C['RESET']}  {C['YELLOW']}CMD {C['GRAY']}│{C['RESET']}  {short}\n"
        f"{C['BLUE']}╚══════════════════════════════════════════════════════════════════════════╝{C['RESET']}\n"
    )


def _print_result_card(command: str, duration: float, exit_code: int,
                       lines: list, timed_out: bool) -> None:
    C = _C
    if timed_out:
        status, icon, sc = "TIMEOUT", "⏱️ ", C['ORANGE']
    elif exit_code == 0:
        status, icon, sc = "SUCCESS", "✅", C['GREEN']
    else:
        status, icon, sc = "FAILED",  "❌", C['RED']

    short = (command[:65] + "…") if len(command) > 68 else command
    output_bytes = sum(len(l.encode()) for l in lines)
    sep = '═' * 74

    _terminal_print(
        f"\n{C['BLUE']}╔═ {sc}{C['BOLD']}{icon} {status}{C['RESET']}{C['BLUE']} {sep}╗{C['RESET']}\n"
        f"{C['BLUE']}║{C['RESET']}  {C['YELLOW']}CMD  {C['GRAY']}│{C['RESET']}  {short}\n"
        f"{C['BLUE']}║{C['RESET']}  {C['CYAN']}TIME {C['GRAY']}│{C['RESET']}  {duration:.3f}s\n"
        f"{C['BLUE']}║{C['RESET']}  {C['BLUE']}SIZE {C['GRAY']}│{C['RESET']}  {output_bytes:,} bytes   "
        f"{C['GRAY']}lines={len(lines)}{C['RESET']}\n"
        f"{C['BLUE']}║{C['RESET']}  {C['WHITE']}EXIT {C['GRAY']}│{C['RESET']}  {exit_code}\n"
        f"{C['BLUE']}╚{'═' * (len(sep) + 12)}╝{C['RESET']}\n"
    )

app = Flask(__name__)
PORT = int(os.environ.get("PROFLUPINMIND_API_PORT", 8887))
HOST = os.environ.get("PROFLUPINMIND_API_HOST", "127.0.0.1")
VERSION = "2.0.0"
_START = time.time()
ALLOW_RAW_COMMAND = os.environ.get("PROFLUPINMIND_ALLOW_RAW_COMMAND", "0").lower() in {"1", "true", "yes"}
REQUIRE_API_KEY = os.environ.get("PROFLUPINMIND_REQUIRE_API_KEY", "0").lower() in {"1", "true", "yes"}
API_KEY = os.environ.get("PROFLUPINMIND_API_KEY", "")

# Extra PATH so Go-based tools (httpx, nuclei, subfinder, …) are found
_TOOL_PATHS = ["/home/kali/go/bin", "/usr/local/bin", "/usr/local/go/bin"]
_cur_path = os.environ.get("PATH", "")
_extra = ":".join(p for p in _TOOL_PATHS if p not in _cur_path)
_ENV = {**os.environ, "PATH": f"{_extra}:{_cur_path}" if _extra else _cur_path}
_SHELL_META_RE = re.compile(r"[;&|`$<>\n\r]")


def _validate_payload_value(value, path: str = "body") -> None:
    if isinstance(value, str):
        if _SHELL_META_RE.search(value):
            raise ValueError(f"{path} contains blocked shell metacharacters")
        return
    if isinstance(value, list):
        for idx, item in enumerate(value):
            _validate_payload_value(item, f"{path}[{idx}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_payload_value(item, f"{path}.{key}")


@app.before_request
def enforce_request_safety():
    if request.path == "/health":
        return None

    if REQUIRE_API_KEY:
        provided = request.headers.get("X-API-Key", "")
        if not API_KEY or not hmac.compare_digest(provided, API_KEY):
            return jsonify({"error": "unauthorized"}), 401

    if request.method in {"POST", "PUT", "PATCH"}:
        payload = request.get_json(silent=True)
        if isinstance(payload, dict):
            try:
                _validate_payload_value(payload)
            except ValueError as exc:
                return jsonify({"error": "unsafe input blocked", "detail": str(exc)}), 400
    return None


# ============================================================================
# CORE EXECUTION (prints every output line live to the server terminal)
# ============================================================================

def _run(command: str, timeout: int = 300) -> dict:
    _print_start_banner(command, timeout)
    start = time.time()
    lines: list[str] = []
    timed_out = False
    master_fd = -1
    slave_fd = -1

    try:
        master_fd, slave_fd = pty.openpty()
        proc = subprocess.Popen(
            command,
            shell=True,
            stdin=subprocess.DEVNULL,
            stdout=slave_fd,
            stderr=slave_fd,
            close_fds=True,
            env=_ENV,
            preexec_fn=os.setsid,
        )
        os.close(slave_fd)
        slave_fd = -1
    except Exception as exc:
        for fd in (master_fd, slave_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        logger.error(f"❌ SPAWN FAILED: {exc}")
        return {"success": False, "error": str(exc), "command": command,
                "output": "", "exit_code": -1, "duration": 0.0, "timed_out": False}

    def _kill_proc():
        nonlocal timed_out
        timed_out = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        msg = f"[TIMEOUT] killed after {timeout}s"
        lines.append(msg)
        _terminal_print(msg)

    timer = threading.Timer(timeout, _kill_proc)
    timer.start()
    try:
        pending = ""
        while True:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            if not chunk:
                break

            pending += chunk.decode("utf-8", errors="replace").replace("\r", "\n")
            while "\n" in pending:
                line, pending = pending.split("\n", 1)
                line = line.rstrip()
                if line:
                    _terminal_print(line)
                    lines.append(line)

            if proc.poll() is not None and not pending:
                break

        if pending.strip():
            line = pending.rstrip()
            _terminal_print(line)
            lines.append(line)
        proc.wait()
    except Exception as exc:
        logger.warning(f"⚠️  read error: {exc}")
    finally:
        timer.cancel()
        if slave_fd >= 0:
            try:
                os.close(slave_fd)
            except OSError:
                pass
        if master_fd >= 0:
            try:
                os.close(master_fd)
            except OSError:
                pass

    duration = round(time.time() - start, 3)
    rc = proc.returncode if proc.returncode is not None else -1
    success = rc == 0 and not timed_out
    _print_result_card(command, duration, rc, lines, timed_out)

    return {
        "success": success,
        "output": "\n".join(lines),
        "exit_code": rc,
        "duration": duration,
        "timed_out": timed_out,
        "command": command,
    }


# ============================================================================
# HEALTH
# ============================================================================

@app.route("/health")
def health():
    return jsonify({
        "status": "healthy",
        "version": VERSION,
        "uptime": round(time.time() - _START, 1),
    })


# ============================================================================
# GENERIC COMMAND
# ============================================================================

@app.route("/api/command", methods=["POST"])
def command():
    if not ALLOW_RAW_COMMAND:
        return jsonify({
            "error": "disabled endpoint",
            "detail": "Set PROFLUPINMIND_ALLOW_RAW_COMMAND=1 to enable /api/command",
        }), 403
    p = request.json or {}
    cmd = p.get("command", "")
    if not cmd:
        return jsonify({"error": "command required"}), 400
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


# ============================================================================
# NETWORK SCANNING
# ============================================================================

@app.route("/api/tools/nmap", methods=["POST"])
@app.route("/api/tools/nmap-root", methods=["POST"])
def nmap():
    p = request.json or {}
    target = p.get("target", "")
    scan_type = p.get("scan_type", "-sV")
    ports = p.get("ports", "")
    scripts = p.get("scripts", "")
    timing = p.get("timing", "T4")
    port_flag = f"-p {ports}" if ports else "--top-ports 1000"
    script_flag = f"--script {scripts}" if scripts else ""
    cmd = f"nmap {scan_type} {port_flag} -{timing} {script_flag} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/rustscan", methods=["POST"])
def rustscan():
    p = request.json or {}
    target = p.get("target", "")
    ports = p.get("ports", "")
    ulimit = p.get("ulimit", 5000)
    nmap_flags = p.get("nmap_flags", "-sV -sC")
    port_flag = f"-p {ports}" if ports else ""
    cmd = f"rustscan -a {target} {port_flag} --ulimit {ulimit} -- {nmap_flags}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/masscan", methods=["POST"])
def masscan():
    p = request.json or {}
    target = p.get("target", "")
    ports = p.get("ports", "0-65535")
    rate = p.get("rate", 1000)
    cmd = f"masscan {target} -p {ports} --rate={rate}"
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/arp-scan", methods=["POST"])
@app.route("/api/tools/arp_scan", methods=["POST"])
def arp_scan():
    p = request.json or {}
    target = p.get("target", "--localnet")
    cmd = f"arp-scan {target}"
    return jsonify(_run(cmd, int(p.get("timeout", 60))))


@app.route("/api/tools/nbtscan", methods=["POST"])
def nbtscan():
    p = request.json or {}
    target = p.get("target", "")
    cmd = f"nbtscan {target}"
    return jsonify(_run(cmd, int(p.get("timeout", 60))))


# ============================================================================
# WEB SCANNING
# ============================================================================

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"nikto -h {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    p = request.json or {}
    target = p.get("target", "")
    mode = p.get("mode", "dir")
    wordlist = p.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    threads = p.get("threads", 50)
    status_codes = p.get("status_codes", "200,301,302,403")
    ext = p.get("extensions", "")
    ext_flag = f"-x {ext}" if ext else ""
    options = p.get("options", "")
    cmd = f"gobuster {mode} -u {target} -w {wordlist} -t {threads} -s {status_codes} {ext_flag} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    p = request.json or {}
    target = p.get("target", "")
    wordlist = p.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    options = p.get("options", "")
    cmd = f"ffuf -u {target}/FUZZ -w {wordlist} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster():
    p = request.json or {}
    target = p.get("target", "")
    wordlist = p.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    options = p.get("options", "")
    cmd = f"feroxbuster -u {target} -w {wordlist} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/dirsearch", methods=["POST"])
def dirsearch():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"dirsearch -u {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    p = request.json or {}
    target = p.get("target", "")
    wordlist = p.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    options = p.get("options", "")
    cmd = f"dirb {target} {wordlist} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    p = request.json or {}
    target = p.get("target", "")
    templates = p.get("templates", "")
    severity = p.get("severity", "")
    template_flag = f"-t {templates}" if templates else ""
    sev_flag = f"-severity {severity}" if severity else ""
    options = p.get("options", "")
    cmd = f"nuclei -u {target} {template_flag} {sev_flag} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 600))))


@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "--batch --level=1 --risk=1")
    cmd = f"sqlmap -u {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/dalfox", methods=["POST"])
def dalfox():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"dalfox url {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    p = request.json or {}
    target = p.get("target", "")
    cmd = f"wafw00f {target}"
    return jsonify(_run(cmd, int(p.get("timeout", 60))))


@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "--enumerate u,ap")
    cmd = f"wpscan --url {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/wfuzz", methods=["POST"])
def wfuzz():
    p = request.json or {}
    target = p.get("target", "")
    wordlist = p.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
    options = p.get("options", "")
    cmd = f"wfuzz -w {wordlist} {options} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


# ============================================================================
# RECON / OSINT
# ============================================================================

@app.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"subfinder -d {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/amass", methods=["POST"])
def amass():
    p = request.json or {}
    target = p.get("target", "")
    mode = p.get("mode", "enum")
    passive = p.get("passive", False)
    passive_flag = "-passive" if passive else ""
    options = p.get("options", "")
    cmd = f"amass {mode} -d {target} {passive_flag} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/dnsenum", methods=["POST"])
def dnsenum():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "--noreverse")
    cmd = f"dnsenum {options} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/fierce", methods=["POST"])
def fierce():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"fierce --domain {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/httpx", methods=["POST"])
def httpx():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "-title -status-code -tech-detect")
    cmd = f"echo '{target}' | httpx {options}"
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/katana", methods=["POST"])
def katana():
    p = request.json or {}
    target = p.get("target", "")
    depth = p.get("depth", 2)
    options = p.get("options", "")
    cmd = f"katana -u {target} -d {depth} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/hakrawler", methods=["POST"])
def hakrawler():
    p = request.json or {}
    target = p.get("target", "")
    depth = p.get("depth", 2)
    cmd = f"echo '{target}' | hakrawler -depth {depth}"
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/gau", methods=["POST"])
def gau():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"gau {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/waybackurls", methods=["POST"])
def waybackurls():
    p = request.json or {}
    target = p.get("target", "")
    cmd = f"echo '{target}' | waybackurls"
    return jsonify(_run(cmd, int(p.get("timeout", 60))))


@app.route("/api/tools/paramspider", methods=["POST"])
def paramspider():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"paramspider -d {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/arjun", methods=["POST"])
def arjun():
    p = request.json or {}
    target = p.get("target", "")
    method = p.get("method", "GET")
    options = p.get("options", "")
    cmd = f"arjun -u {target} -m {method} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/x8", methods=["POST"])
def x8():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"x8 -u {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


# ============================================================================
# SMB / WINDOWS
# ============================================================================

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "-a")
    cmd = f"enum4linux {options} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/enum4linux-ng", methods=["POST"])
@app.route("/api/tools/enum4linux_ng", methods=["POST"])
def enum4linux_ng():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "-A")
    cmd = f"enum4linux-ng {options} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/smbmap", methods=["POST"])
def smbmap():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"smbmap -H {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 60))))


@app.route("/api/tools/rpcclient", methods=["POST"])
def rpcclient():
    p = request.json or {}
    target = p.get("target", "")
    command_str = p.get("commands", "enumdomusers")
    cmd = f"rpcclient -U '' -N {target} -c '{command_str}'"
    return jsonify(_run(cmd, int(p.get("timeout", 60))))


@app.route("/api/tools/netexec", methods=["POST"])
def netexec():
    p = request.json or {}
    target = p.get("target", "")
    protocol = p.get("protocol", "smb")
    options = p.get("options", "")
    cmd = f"netexec {protocol} {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/responder", methods=["POST"])
def responder():
    p = request.json or {}
    interface = p.get("interface", "eth0")
    options = p.get("options", "-rdw")
    cmd = f"responder -I {interface} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


# ============================================================================
# EXPLOITATION
# ============================================================================

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    p = request.json or {}
    target = p.get("target", "")
    service = p.get("service", "ssh")
    userlist = p.get("userlist", "")
    passlist = p.get("passlist", "/usr/share/wordlists/rockyou.txt")
    options = p.get("options", "")
    user_flag = f"-L {userlist}" if userlist else "-l admin"
    cmd = f"hydra {user_flag} -P {passlist} {target} {service} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/hashcat", methods=["POST"])
def hashcat():
    p = request.json or {}
    hash_file = p.get("hash_file", "")
    hash_type = p.get("hash_type", 0)
    attack_mode = p.get("attack_mode", 0)
    wordlist = p.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    rules = p.get("rules", "")
    options = p.get("options", "")
    rules_flag = f"-r {rules}" if rules else ""
    cmd = f"hashcat -m {hash_type} -a {attack_mode} {rules_flag} {options} {hash_file} {wordlist}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/john", methods=["POST"])
def john():
    p = request.json or {}
    hash_file = p.get("hash_file", "")
    wordlist = p.get("wordlist", "/usr/share/wordlists/rockyou.txt")
    options = p.get("options", "")
    cmd = f"john {hash_file} --wordlist={wordlist} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    p = request.json or {}
    commands = p.get("commands", "version")
    cmd = f"msfconsole -q -x '{commands}; exit'"
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/msfvenom", methods=["POST"])
def msfvenom():
    p = request.json or {}
    payload = p.get("payload", "")
    lhost = p.get("lhost", "127.0.0.1")
    lport = p.get("lport", "4444")
    output_file = p.get("output_file", "")
    options = p.get("options", "")
    out_flag = f"-o {output_file}" if output_file else ""
    cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} {out_flag} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


# ============================================================================
# BINARY ANALYSIS
# ============================================================================

@app.route("/api/tools/binwalk", methods=["POST"])
def binwalk():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "-e")
    cmd = f"binwalk {options} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/strings", methods=["POST"])
def strings_extract():
    p = request.json or {}
    target = p.get("target", "")
    min_length = p.get("min_length", 4)
    options = p.get("options", "")
    cmd = f"strings -n {min_length} {options} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 30))))


@app.route("/api/tools/xxd", methods=["POST"])
def xxd():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"xxd {options} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 30))))


@app.route("/api/tools/objdump", methods=["POST"])
def objdump():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "-d")
    cmd = f"objdump {options} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 60))))


@app.route("/api/tools/checksec", methods=["POST"])
def checksec():
    p = request.json or {}
    target = p.get("target", "")
    cmd = f"checksec --file={target}"
    return jsonify(_run(cmd, int(p.get("timeout", 30))))


@app.route("/api/tools/radare2", methods=["POST"])
def radare2():
    p = request.json or {}
    target = p.get("target", "")
    commands = p.get("commands", "aaa;afl;q")
    cmd = f"r2 -q -c '{commands}' {target}"
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/gdb", methods=["POST"])
def gdb():
    import tempfile
    p = request.json or {}
    target = p.get("target", "")
    commands = p.get("commands", "info functions\nquit")
    commands = commands.replace(";", "\n")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(commands + "\n")
        cmd_file = f.name
    cmd = f"gdb -batch -x {cmd_file} {target}"
    result = _run(cmd, int(p.get("timeout", 60)))
    try:
        os.unlink(cmd_file)
    except Exception:
        pass
    return jsonify(result)


@app.route("/api/tools/ghidra", methods=["POST"])
def ghidra():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    project_dir = p.get("project_dir", "/tmp/ghidra_projects")
    cmd = f"analyzeHeadless {project_dir} proflupinmind_project -import {target} {options} -deleteProject"
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/ropgadget", methods=["POST"])
def ropgadget():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"ROPgadget --binary {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 60))))


@app.route("/api/tools/ropper", methods=["POST"])
def ropper():
    p = request.json or {}
    target = p.get("target", "")
    options = p.get("options", "")
    cmd = f"ropper --file {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 60))))


# ============================================================================
# FORENSICS
# ============================================================================

@app.route("/api/tools/exiftool", methods=["POST"])
def exiftool():
    p = request.json or {}
    target = p.get("target", "")
    cmd = f"exiftool {target}"
    return jsonify(_run(cmd, int(p.get("timeout", 30))))


@app.route("/api/tools/steghide", methods=["POST"])
def steghide():
    p = request.json or {}
    target = p.get("target", "")
    passphrase = p.get("passphrase", "")
    if passphrase:
        cmd = f"steghide extract -sf {target} -p '{passphrase}'"
    else:
        cmd = f"steghide info {target}"
    return jsonify(_run(cmd, int(p.get("timeout", 30))))


@app.route("/api/tools/foremost", methods=["POST"])
def foremost():
    p = request.json or {}
    target = p.get("target", "")
    output_dir = p.get("output_dir", "/tmp/foremost_out")
    cmd = f"foremost -i {target} -o {output_dir}"
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/volatility", methods=["POST"])
def volatility():
    p = request.json or {}
    target = p.get("target", "")
    plugin = p.get("plugin", "imageinfo")
    options = p.get("options", "")
    cmd = f"volatility -f {target} {plugin} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/volatility3", methods=["POST"])
def volatility3():
    p = request.json or {}
    target = p.get("target", "")
    plugin = p.get("plugin", "windows.info")
    options = p.get("options", "")
    cmd = f"vol -f {target} {plugin} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


# ============================================================================
# CLOUD SECURITY
# ============================================================================

@app.route("/api/tools/trivy", methods=["POST"])
def trivy():
    p = request.json or {}
    target = p.get("target", "")
    scan_type = p.get("scan_type", "image")
    options = p.get("options", "")
    cmd = f"trivy {scan_type} {options} {target}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/prowler", methods=["POST"])
def prowler():
    p = request.json or {}
    options = p.get("options", "")
    cmd = f"prowler {options}".strip() or "prowler"
    return jsonify(_run(cmd, int(p.get("timeout", 300))))


@app.route("/api/tools/checkov", methods=["POST"])
def checkov():
    p = request.json or {}
    target = p.get("target", ".")
    options = p.get("options", "")
    cmd = f"checkov -d {target} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


@app.route("/api/tools/docker-bench", methods=["POST"])
@app.route("/api/tools/docker_bench", methods=["POST"])
def docker_bench():
    p = request.json or {}
    cmd = "docker-bench-security"
    return jsonify(_run(cmd, int(p.get("timeout", 120))))


# ============================================================================
# JWT / API
# ============================================================================

@app.route("/api/tools/jwt", methods=["POST"])
def jwt():
    p = request.json or {}
    token = p.get("token", "")
    options = p.get("options", "-d")
    cmd = f"jwt_tool {token} {options}".strip()
    return jsonify(_run(cmd, int(p.get("timeout", 30))))


# ============================================================================
# ENTRY POINT
# ============================================================================

def start(host: str = HOST, port: int = PORT):
    logger.info(f"\n{'='*60}")
    logger.info(f"  ProfLupinMind API Server v{VERSION}")
    logger.info(f"  Listening : http://{host}:{port}")
    logger.info(f"  Health    : http://{host}:{port}/health")
    logger.info(f"{'='*60}\n")
    app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)


if __name__ == "__main__":
    start()
