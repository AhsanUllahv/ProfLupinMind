"""
Intelligent Error Handler — classifies tool errors, suggests recovery strategies,
maps tool alternatives, and provides graceful degradation fallback chains.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ErrorType(str, Enum):
    TIMEOUT           = "timeout"
    PERMISSION        = "permission"
    NETWORK           = "network"
    RATE_LIMIT        = "rate_limit"
    TOOL_NOT_FOUND    = "tool_not_found"
    INVALID_PARAMS    = "invalid_params"
    RESOURCE_EXHAUSTED= "resource_exhausted"
    AUTH_FAILED       = "auth_failed"
    TARGET_UNREACHABLE= "target_unreachable"
    PARSING_ERROR     = "parsing_error"
    UNKNOWN           = "unknown"


# ─── Error Patterns ───────────────────────────────────────────────────────────

ERROR_PATTERNS: dict[ErrorType, list[str]] = {
    ErrorType.TIMEOUT: [
        r"timed?\s*out", r"connection timed out", r"timeout", r"TIMEOUT",
        r"Killed", r"signal 9", r"took too long",
    ],
    ErrorType.PERMISSION: [
        r"permission denied", r"operation not permitted", r"access denied",
        r"you must be root", r"sudo required", r"EPERM",
        r"requires root", r"run as root",
    ],
    ErrorType.NETWORK: [
        r"connection refused", r"network unreachable", r"no route to host",
        r"name or service not known", r"could not resolve",
        r"ECONNREFUSED", r"ENETUNREACH", r"EHOSTUNREACH",
    ],
    ErrorType.RATE_LIMIT: [
        r"rate limit", r"too many requests", r"429",
        r"throttl", r"slow down", r"blocked by",
    ],
    ErrorType.TOOL_NOT_FOUND: [
        r"command not found", r"no such file or directory",
        r"not installed", r"which: no", r"executable not found",
    ],
    ErrorType.INVALID_PARAMS: [
        r"invalid option", r"unrecognized option", r"unknown flag",
        r"usage:", r"error: argument", r"invalid argument",
    ],
    ErrorType.RESOURCE_EXHAUSTED: [
        r"out of memory", r"cannot allocate", r"disk full",
        r"no space left", r"too many open files", r"ENOMEM",
    ],
    ErrorType.AUTH_FAILED: [
        r"authentication failed", r"invalid credentials", r"login failed",
        r"unauthorized", r"401", r"403 forbidden",
    ],
    ErrorType.TARGET_UNREACHABLE: [
        r"host is down", r"0 hosts up", r"filtered",
        r"destination unreachable", r"no response",
    ],
    ErrorType.PARSING_ERROR: [
        r"parse error", r"invalid json", r"xml parse",
        r"unexpected token", r"syntax error",
    ],
}

# ─── Recovery Strategies ──────────────────────────────────────────────────────

RECOVERY_STRATEGIES: dict[ErrorType, list[str]] = {
    ErrorType.TIMEOUT: [
        "Increase timeout with --timeout flag",
        "Reduce scan scope (fewer ports or targets)",
        "Use a faster/lighter alternative tool",
        "Split the target range into smaller chunks",
        "Run with -T3 instead of -T4 (slower but completes)",
    ],
    ErrorType.PERMISSION: [
        "Prepend 'sudo' to the command",
        "Run as root user",
        "Use a non-privileged alternative (e.g. connect scan instead of SYN scan)",
        "Check if the tool requires CAP_NET_RAW capability",
        "Use user-mode scan option (-sT for nmap)",
    ],
    ErrorType.NETWORK: [
        "Verify the target is reachable with 'ping'",
        "Check DNS resolution with 'nslookup'",
        "Try using the IP address instead of hostname",
        "Check firewall rules",
        "Confirm VPN or proxy is not blocking traffic",
    ],
    ErrorType.RATE_LIMIT: [
        "Reduce request rate (--rate, --delay, -T2)",
        "Add random delays between requests",
        "Use a proxy or rotate IPs",
        "Wait 60 seconds and retry",
        "Use passive reconnaissance instead",
    ],
    ErrorType.TOOL_NOT_FOUND: [
        "Install the tool: apt-get install <tool>",
        "Check PATH: which <tool>",
        "Use an alternative tool from the list",
        "Check pip/gem/go install for non-apt tools",
    ],
    ErrorType.INVALID_PARAMS: [
        "Check tool version: <tool> --version",
        "Review syntax: <tool> --help",
        "Remove conflicting flags",
        "Use shorter/simpler parameter set",
    ],
    ErrorType.RESOURCE_EXHAUSTED: [
        "Reduce thread count",
        "Free up disk/memory before retrying",
        "Use --ulimit to cap open files",
        "Run lighter tool or reduce scan depth",
    ],
    ErrorType.AUTH_FAILED: [
        "Verify credentials are correct",
        "Try default credentials list",
        "Check if account is locked (too many attempts)",
        "Use a different authentication method",
    ],
    ErrorType.TARGET_UNREACHABLE: [
        "Verify target is online",
        "Try ICMP ping then TCP ping (-Pn in nmap)",
        "Check if host blocks ICMP",
        "Use a different source port",
    ],
    ErrorType.PARSING_ERROR: [
        "Update the tool to latest version",
        "Use --output raw flag",
        "Manually inspect the response",
        "Try a different output format",
    ],
    ErrorType.UNKNOWN: [
        "Check tool documentation",
        "Try with verbose output (-v or --verbose)",
        "Run with minimum options first",
        "Check tool version compatibility",
    ],
}

# ─── Tool Alternatives ────────────────────────────────────────────────────────

TOOL_ALTERNATIVES: dict[str, list[str]] = {
    "nmap":        ["rustscan", "masscan", "netcat"],
    "masscan":     ["nmap", "rustscan", "zmap"],
    "rustscan":    ["nmap", "masscan"],
    "gobuster":    ["feroxbuster", "ffuf", "dirsearch", "dirb"],
    "feroxbuster": ["gobuster", "ffuf", "dirsearch"],
    "ffuf":        ["gobuster", "feroxbuster", "wfuzz"],
    "dirsearch":   ["gobuster", "feroxbuster", "ffuf"],
    "nikto":       ["nuclei", "whatweb", "zaproxy"],
    "nuclei":      ["nikto", "jaeles", "zaproxy"],
    "sqlmap":      ["ghauri", "nosqlmap"],
    "wpscan":      ["nuclei", "nikto"],
    "hydra":       ["medusa", "ncrack", "patator"],
    "medusa":      ["hydra", "ncrack"],
    "hashcat":     ["john"],
    "john":        ["hashcat"],
    "amass":       ["subfinder", "assetfinder", "findomain"],
    "subfinder":   ["amass", "assetfinder", "findomain"],
    "metasploit":  ["searchsploit", "msfvenom"],
    "enum4linux":  ["enum4linux-ng", "smbmap", "rpcclient"],
    "smbmap":      ["enum4linux", "rpcclient"],
    "binwalk":     ["foremost", "strings", "file"],
    "ghidra":      ["radare2", "objdump"],
    "radare2":     ["ghidra", "objdump", "gdb"],
    "gdb":         ["pwndbg", "peda", "radare2"],
    "prowler":     ["scout-suite", "pacu"],
    "scout-suite": ["prowler"],
    "trivy":       ["clair", "grype", "snyk"],
    "kube-hunter": ["kube-bench", "trivy"],
    "dalfox":      ["xsser", "xsstrike"],
    "katana":      ["hakrawler", "gospider", "gau"],
    "httpx":       ["curl", "wget"],
}

# ─── Parameter Adjustments on Error ──────────────────────────────────────────

PARAM_ADJUSTMENTS: dict[tuple[str, ErrorType], dict[str, Any]] = {
    ("nmap",    ErrorType.TIMEOUT):     {"remove": ["-T5", "-T4"], "add": ["-T2", "--max-retries 1"]},
    ("nmap",    ErrorType.PERMISSION):  {"remove": ["-sS", "-O"], "add": ["-sT", "-Pn"]},
    ("nmap",    ErrorType.TARGET_UNREACHABLE): {"add": ["-Pn", "--disable-arp-ping"]},
    ("gobuster",ErrorType.RATE_LIMIT):  {"remove": ["-t 50"], "add": ["-t 10", "--delay 200ms"]},
    ("ffuf",    ErrorType.RATE_LIMIT):  {"remove": ["-rate 500"], "add": ["-rate 50", "-p 0.5"]},
    ("hydra",   ErrorType.RATE_LIMIT):  {"remove": ["-t 16"], "add": ["-t 4", "-W 3"]},
    ("sqlmap",  ErrorType.RATE_LIMIT):  {"add": ["--delay=3", "--safe-freq=1"]},
    ("masscan", ErrorType.RATE_LIMIT):  {"remove": ["--rate 10000"], "add": ["--rate 100"]},
}


# ─── Error Handler ────────────────────────────────────────────────────────────

@dataclass
class ErrorContext:
    tool:          str
    command:       str
    output:        str
    exit_code:     int
    duration:      float
    error_type:    ErrorType        = ErrorType.UNKNOWN
    strategies:    list[str]        = field(default_factory=list)
    alternatives:  list[str]        = field(default_factory=list)
    param_fix:     dict[str, Any]   = field(default_factory=dict)
    escalate:      bool             = False
    message:       str              = ""


class IntelligentErrorHandler:

    def __init__(self) -> None:
        self._history: list[ErrorContext] = []

    def classify(self, tool: str, command: str, output: str,
                 exit_code: int, duration: float) -> ErrorContext:
        error_type = self._detect_error_type(output, exit_code, duration)
        strategies = RECOVERY_STRATEGIES.get(error_type, RECOVERY_STRATEGIES[ErrorType.UNKNOWN])
        alternatives = TOOL_ALTERNATIVES.get(tool, [])
        param_fix = PARAM_ADJUSTMENTS.get((tool, error_type), {})
        escalate = error_type in {ErrorType.RESOURCE_EXHAUSTED, ErrorType.UNKNOWN} and exit_code != 0
        message = self._build_message(tool, error_type, strategies, alternatives)

        ctx = ErrorContext(
            tool=tool, command=command, output=output,
            exit_code=exit_code, duration=duration,
            error_type=error_type, strategies=strategies,
            alternatives=alternatives, param_fix=param_fix,
            escalate=escalate, message=message,
        )
        self._history.append(ctx)
        return ctx

    def _detect_error_type(self, output: str, exit_code: int, duration: float) -> ErrorType:
        combined = output.lower()
        for etype, patterns in ERROR_PATTERNS.items():
            if any(re.search(p, combined, re.IGNORECASE) for p in patterns):
                return etype
        # Heuristic: very long duration with non-zero exit → timeout
        if duration > 280 and exit_code != 0:
            return ErrorType.TIMEOUT
        if exit_code == 0:
            return ErrorType.PARSING_ERROR  # success but we're here — parsing issue
        return ErrorType.UNKNOWN

    def _build_message(self, tool: str, etype: ErrorType,
                       strategies: list[str], alternatives: list[str]) -> str:
        lines = [
            f"🔍 Error type: {etype.value.replace('_', ' ').upper()}",
            "",
            "💡 Recovery strategies:",
        ]
        for i, s in enumerate(strategies[:3], 1):
            lines.append(f"  {i}. {s}")
        if alternatives:
            lines.append(f"\n🔄 Alternative tools: {', '.join(alternatives[:3])}")
        return "\n".join(lines)

    def get_statistics(self) -> dict[str, Any]:
        if not self._history:
            return {"total": 0}
        from collections import Counter
        counts = Counter(c.error_type.value for c in self._history)
        return {
            "total":    len(self._history),
            "by_type":  dict(counts),
            "escalated": sum(1 for c in self._history if c.escalate),
        }

    def to_dict(self, ctx: ErrorContext) -> dict[str, Any]:
        return {
            "tool":         ctx.tool,
            "error_type":   ctx.error_type.value,
            "strategies":   ctx.strategies,
            "alternatives": ctx.alternatives,
            "param_fix":    ctx.param_fix,
            "escalate":     ctx.escalate,
            "message":      ctx.message,
        }


# ─── Graceful Degradation ─────────────────────────────────────────────────────

# Fallback chains: primary tool → ordered list of fallbacks
FALLBACK_CHAINS: dict[str, list[str]] = {
    "port_scan":        ["nmap", "rustscan", "masscan", "netcat"],
    "dir_bust":         ["gobuster", "feroxbuster", "ffuf", "dirsearch", "dirb"],
    "subdomain_enum":   ["subfinder", "amass", "assetfinder", "findomain"],
    "vuln_scan":        ["nuclei", "nikto", "jaeles"],
    "web_crawl":        ["katana", "hakrawler", "gospider", "gau"],
    "password_crack":   ["hashcat", "john"],
    "brute_force":      ["hydra", "medusa", "ncrack"],
    "smb_enum":         ["enum4linux", "smbmap", "rpcclient"],
    "cloud_audit":      ["prowler", "scout-suite"],
    "container_scan":   ["trivy", "clair", "grype"],
    "static_analysis":  ["radare2", "ghidra", "objdump"],
    "dynamic_analysis": ["gdb", "pwntools"],
    "sql_injection":    ["sqlmap", "ghauri"],
    "xss_scan":         ["dalfox", "xsser", "xsstrike"],
    "param_discovery":  ["arjun", "x8", "paramspider"],
}

# Basic manual fallback commands when all tools fail
MANUAL_FALLBACKS: dict[str, str] = {
    "port_scan":      "nc -zv {target} {port_range}",
    "dir_bust":       "for p in admin login wp-admin .env config backup; do curl -s -o /dev/null -w '%{{http_code}} '\"$p\" {target}/$p; done",
    "subdomain_enum": "for sub in www mail ftp dev api admin; do host $sub.{domain}; done",
    "brute_force":    "while read pass; do curl -s -d 'user=admin&pass='$pass {target}/login | grep -q 'Welcome' && echo $pass; done < /tmp/passwords.txt",
}


class GracefulDegradation:

    def get_fallback_chain(self, operation: str) -> list[str]:
        """Return ordered list of fallback tools for an operation."""
        return FALLBACK_CHAINS.get(operation, [])

    def next_tool(self, operation: str, failed_tools: list[str]) -> str | None:
        """Return the next untried tool in the fallback chain."""
        chain = self.get_fallback_chain(operation)
        for tool in chain:
            if tool not in failed_tools:
                return tool
        return None

    def get_manual_fallback(self, operation: str, target: str = "", **kwargs) -> str | None:
        """Return a manual shell command when all tools have failed."""
        template = MANUAL_FALLBACKS.get(operation)
        if not template:
            return None
        try:
            return template.format(target=target, domain=target.lstrip("*."), **kwargs)
        except KeyError:
            return template

    def apply_partial_results(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Merge partial results from multiple fallback attempts."""
        merged: dict[str, Any] = {"sources": [], "data": {}}
        for r in results:
            if r.get("output"):
                merged["sources"].append(r.get("tool", "unknown"))
                merged["data"][r.get("tool", "unknown")] = r.get("output", "")
        merged["coverage"] = f"{len(merged['sources'])} tool(s) contributed data"
        return merged

    def suggest_manual_steps(self, operation: str, target: str) -> list[str]:
        """Human-readable manual steps when full automation fails."""
        steps_map: dict[str, list[str]] = {
            "port_scan": [
                f"Run: nc -zv {target} 1-1024",
                "Use an online port scanner (Shodan, Censys)",
                "Try: curl -I http://{target} to check HTTP",
            ],
            "dir_bust": [
                f"Manually browse {target}/robots.txt and {target}/sitemap.xml",
                "Check source code for hidden links",
                f"Try common paths: {target}/admin, {target}/login, {target}/.env",
            ],
            "subdomain_enum": [
                "Check Certificate Transparency logs at crt.sh",
                "Search Shodan for the domain",
                "Check DNS records: dig ANY {target}",
            ],
        }
        return steps_map.get(operation, ["Manual investigation required — automated tools failed"])
