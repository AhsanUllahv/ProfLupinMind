#!/usr/bin/env python3
"""Quick tool availability checker for ProfLupinMind.

Checks every tool binary with `which` + a fast version probe.
No network target needed — completes in seconds.

Usage:
    python3 test_tools.py
    python3 test_tools.py --api        # also hit Flask API endpoints
    python3 test_tools.py --api-url http://127.0.0.1:8887
"""

import argparse
import shutil
import subprocess
import sys
import time
import requests

# ── ANSI colours ──────────────────────────────────────────────────────────────
G = "\033[92m"   # green
R = "\033[91m"   # red
Y = "\033[93m"   # yellow
B = "\033[94m"   # blue
BOLD = "\033[1m"
RST = "\033[0m"


def _run(cmd: str, timeout: int = 5) -> bool:
    """Return True if cmd exits 0 (or 1 — many tools exit 1 for --help)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=timeout
        )
        return r.returncode in (0, 1)
    except Exception:
        return False


# ── Tool registry ─────────────────────────────────────────────────────────────
# Format: (binary_name, quick_version_command)
TOOLS: dict[str, list[tuple[str, str]]] = {
    "Network Scanning": [
        ("nmap",          "nmap --version"),
        ("rustscan",      "rustscan --version"),
        ("masscan",       "masscan --version"),
        ("arp-scan",      "arp-scan --version"),
        ("nbtscan",       "nbtscan 2>&1 | head -1"),
        ("onesixtyone",   "onesixtyone 2>&1 | head -1"),
        ("snmpwalk",      "snmpwalk --version"),
    ],
    "Web Scanning / Dir Bruteforce": [
        ("nikto",         "nikto -Version"),
        ("gobuster",      "gobuster version"),
        ("ffuf",          "ffuf -V"),
        ("feroxbuster",   "feroxbuster --version"),
        ("dirsearch",     "dirsearch --version 2>&1 | head -1"),
        ("dirb",          "dirb 2>&1 | head -1"),
        ("wfuzz",         "wfuzz --version 2>&1 | head -1"),
        ("dotdotpwn",     "dotdotpwn.pl -h 2>&1 | head -1"),
        ("jaeles",        "jaeles version"),
        ("zaproxy",       "zaproxy -version 2>&1 | head -1"),
    ],
    "Vulnerability Scanning": [
        ("nuclei",        "nuclei -version"),
        ("sqlmap",        "sqlmap --version"),
        ("dalfox",        "dalfox version"),
        ("xsser",         "xsser --version 2>&1 | head -1"),
        ("wafw00f",       "wafw00f --version 2>&1 | head -1"),
        ("wpscan",        "wpscan --version"),
        ("graphqlmap",    "graphqlmap --help 2>&1 | head -1"),
    ],
    "Recon / OSINT": [
        ("subfinder",     "subfinder -version"),
        ("amass",         "amass -version"),
        ("dnsenum",       "dnsenum --version 2>&1 | head -1"),
        ("fierce",        "fierce --help 2>&1 | head -1"),
        ("httpx",         "httpx -version"),
        ("katana",        "katana -version"),
        ("hakrawler",     "hakrawler --help 2>&1 | head -1"),
        ("gau",           "gau --version"),
        ("waybackurls",   "waybackurls --help 2>&1 | head -1"),
        ("paramspider",   "paramspider --version 2>&1 | head -1"),
        ("arjun",         "arjun --help 2>&1 | head -1"),
        ("x8",            "x8 --help 2>&1 | head -1"),
    ],
    "URL / Param Utilities": [
        ("anew",          "anew --help 2>&1 | head -1"),
        ("uro",           "uro --version 2>&1 | head -1"),
        ("qsreplace",     "qsreplace --help 2>&1 | head -1"),
    ],
    "SMB / Windows": [
        ("enum4linux",    "enum4linux 2>&1 | head -1"),
        ("enum4linux-ng", "enum4linux-ng --version 2>&1 | head -1"),
        ("smbmap",        "smbmap --version 2>&1 | head -1"),
        ("smbclient",     "smbclient --version"),
        ("rpcclient",     "rpcclient --version"),
        ("netexec",       "netexec --version"),
        ("responder",     "responder --version 2>&1 | head -1"),
    ],
    "Exploitation": [
        ("hydra",         "hydra -h 2>&1 | head -1"),
        ("hashcat",       "hashcat --version"),
        ("john",          "john --version 2>&1 | head -1"),
        ("hashpump",      "hashpump --help 2>&1 | head -1"),
        ("msfconsole",    "msfconsole --version"),
        ("msfvenom",      "msfvenom --version"),
        ("pacu",          "pacu --help 2>&1 | head -1"),
        ("pwninit",       "pwninit --help 2>&1 | head -1"),
    ],
    "Binary Analysis / Rev Eng": [
        ("binwalk",       "binwalk --version"),
        ("strings",       "strings --version 2>&1 | head -1"),
        ("xxd",           "xxd -v 2>&1 | head -1"),
        ("objdump",       "objdump --version | head -1"),
        ("checksec",      "checksec --version 2>&1 | head -1"),
        ("r2",            "r2 -version 2>&1 | head -1"),
        ("gdb",           "gdb --version | head -1"),
        ("ROPgadget",     "ROPgadget --version"),
        ("ropper",        "ropper --version"),
        ("angr",          "python3 -c 'import angr; print(angr.__version__)'"),
        ("one_gadget",    "one_gadget --version"),
    ],
    "Forensics": [
        ("exiftool",      "exiftool -ver"),
        ("steghide",      "steghide --version 2>&1 | head -1"),
        ("foremost",      "foremost -h 2>&1 | head -1"),
        ("volatility",    "volatility --info 2>&1 | head -1"),
        ("vol",           "vol --version 2>&1 | head -1"),
    ],
    "Cloud / Container Security": [
        ("trivy",         "trivy --version"),
        ("prowler",       "prowler -v 2>&1 | head -1"),
        ("checkov",       "checkov --version"),
        ("terrascan",     "terrascan version"),
        ("kube-bench",    "kube-bench version"),
        ("kube-hunter",   "kube-hunter --help 2>&1 | head -1"),
    ],
    "JWT / API": [
        ("jwt_tool",      "jwt_tool --help 2>&1 | head -1"),
    ],
    "Passwords / Hashing": [
        ("hashid",        "hashid --version 2>&1 | head -1"),
        ("hash-identifier", "hash-identifier --help 2>&1 | head -1"),
    ],
    "Python Libraries (pwntools etc.)": [
        ("pwntools",      "python3 -c 'import pwn; print(pwn.__version__)'"),
        ("pwndbg",        "python3 -c 'import pwndbg; print(\"ok\")' 2>&1 | head -1"),
    ],
}

# Flask API endpoint smoke-tests (harmless calls)
API_TESTS: list[tuple[str, str, dict]] = [
    ("nmap",       "/api/tools/nmap",       {"target": "127.0.0.1", "scan_type": "-sn", "ports": ""}),
    ("httpx",      "/api/tools/httpx",      {"target": "127.0.0.1", "options": "-silent"}),
    ("subfinder",  "/api/tools/subfinder",  {"target": "example.com", "options": "-silent"}),
    ("health",     "/health",               None),
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def check_binary(binary: str) -> bool:
    """True if binary is on PATH."""
    # handle python import checks
    if binary in ("pwntools", "pwndbg", "angr"):
        return False  # handled via version cmd
    return shutil.which(binary) is not None


def probe_version(cmd: str) -> str:
    """Return first non-empty output line or error snippet."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=6
        )
        out = (r.stdout + r.stderr).strip()
        first = next((l.strip() for l in out.splitlines() if l.strip()), "")
        return first[:80] if first else "(no output)"
    except subprocess.TimeoutExpired:
        return "(timeout)"
    except Exception as e:
        return f"(error: {e})"


def api_test(base_url: str, path: str, body: dict | None, timeout: int = 10) -> tuple[bool, str]:
    url = base_url.rstrip("/") + path
    try:
        if body is None:
            r = requests.get(url, timeout=timeout)
        else:
            r = requests.post(url, json=body, timeout=timeout)
        ok = r.status_code == 200
        data = r.json() if ok else {}
        detail = data.get("output", data.get("status", str(r.status_code)))[:60]
        return ok, detail
    except requests.ConnectionError:
        return False, "connection refused"
    except Exception as e:
        return False, str(e)[:60]


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="ProfLupinMind tool availability checker")
    parser.add_argument("--api", action="store_true", help="Also smoke-test Flask API endpoints")
    parser.add_argument("--api-url", default="http://127.0.0.1:8887", help="Flask API base URL")
    parser.add_argument("--version", action="store_true", help="Show version string for each tool")
    args = parser.parse_args()

    total = found = 0
    category_summary: list[tuple[str, int, int]] = []

    print(f"\n{BOLD}{'='*70}{RST}")
    print(f"{BOLD}  ProfLupinMind Tool Availability Check{RST}")
    print(f"{BOLD}{'='*70}{RST}\n")

    for category, tools in TOOLS.items():
        cat_found = 0
        print(f"{BOLD}{B}▶ {category}{RST}")
        for binary, ver_cmd in tools:
            total += 1
            on_path = check_binary(binary)
            # for python imports, try the ver_cmd directly
            if not on_path and binary in ("pwntools", "pwndbg", "angr"):
                ver_out = probe_version(ver_cmd)
                on_path = "error" not in ver_out.lower() and "module" not in ver_out.lower()

            if on_path:
                found += 1
                cat_found += 1
                if args.version:
                    ver = probe_version(ver_cmd)
                    print(f"  {G}✅ {binary:<20}{RST} {ver}")
                else:
                    print(f"  {G}✅ {binary}{RST}")
            else:
                print(f"  {R}❌ {binary}{RST}")

        category_summary.append((category, cat_found, len(tools)))
        print()

    # ── API smoke-tests ──────────────────────────────────────────────────────
    if args.api:
        print(f"{BOLD}{B}▶ Flask API Smoke-Tests  ({args.api_url}){RST}")
        for name, path, body in API_TESTS:
            ok, detail = api_test(args.api_url, path, body, timeout=15)
            status = f"{G}✅" if ok else f"{R}❌"
            print(f"  {status} {name:<20}{RST} {detail}")
        print()

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"{BOLD}{'='*70}{RST}")
    print(f"{BOLD}  SUMMARY{RST}")
    print(f"{BOLD}{'='*70}{RST}")
    for cat, cat_found, cat_total in category_summary:
        bar = "█" * cat_found + "░" * (cat_total - cat_found)
        colour = G if cat_found == cat_total else (Y if cat_found > 0 else R)
        print(f"  {colour}{bar}{RST}  {cat_found}/{cat_total}  {cat}")

    pct = int(found / total * 100) if total else 0
    colour = G if pct >= 80 else (Y if pct >= 50 else R)
    print(f"\n  {BOLD}Overall: {colour}{found}/{total} tools installed ({pct}%){RST}\n")


if __name__ == "__main__":
    t0 = time.time()
    main()
    print(f"  Completed in {time.time()-t0:.1f}s\n")
