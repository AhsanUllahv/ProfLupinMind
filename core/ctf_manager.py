"""
CTF Manager — per-category workflow generation, tool suggestion,
auto-solver strategy, and flag extraction.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ─── CTF Categories ───────────────────────────────────────────────────────────

CTF_CATEGORIES = ["web", "crypto", "pwn", "forensics", "rev", "misc", "osint", "blockchain"]

# ─── Tool Maps per Category ───────────────────────────────────────────────────

CATEGORY_TOOLS: dict[str, list[str]] = {
    "web": [
        "gobuster", "ffuf", "nikto", "sqlmap", "dalfox", "nuclei",
        "wfuzz", "httpx", "feroxbuster", "burpsuite", "zaproxy",
        "arjun", "jwt-analyzer", "katana",
    ],
    "crypto": [
        "hashcat", "john", "hashpump", "openssl", "python3",
        "rsactftool", "factordb",
    ],
    "pwn": [
        "gdb", "pwntools", "radare2", "ghidra", "pwndbg", "peda",
        "checksec", "ropper", "one-gadget", "ropgadget", "pwninit",
        "patchelf", "libc-database",
    ],
    "forensics": [
        "binwalk", "strings", "file", "xxd", "exiftool", "volatility3",
        "foremost", "photorec", "steghide", "stegsolve", "zsteg",
        "wireshark", "tshark", "bulk-extractor", "autopsy",
    ],
    "rev": [
        "ghidra", "radare2", "gdb", "objdump", "strings", "ltrace",
        "strace", "file", "binwalk", "python3", "angr",
    ],
    "misc": [
        "python3", "curl", "netcat", "base64", "xxd", "strings",
        "file", "binwalk",
    ],
    "osint": [
        "theharvester", "subfinder", "amass", "shodan", "maltego",
        "spiderfoot", "sherlock", "social-analyzer",
    ],
    "blockchain": [
        "python3", "web3", "mythril", "slither",
    ],
}

# ─── Per-Category Solving Strategies ─────────────────────────────────────────

CATEGORY_STRATEGIES: dict[str, list[str]] = {
    "web": [
        "Enumerate all endpoints with gobuster/ffuf",
        "Check robots.txt, .git/, .env, backup files",
        "Test all input fields for SQLi, XSS, SSTI",
        "Inspect cookies, JWTs, and session tokens",
        "Look for IDOR by changing object IDs",
        "Test file upload with bypass techniques",
        "Check for SSRF via URL parameters",
        "Fuzz HTTP headers (X-Forwarded-For, Host)",
        "Analyse JavaScript source for hidden endpoints/keys",
        "Try default credentials on admin panels",
        "Look for LFI in file/page parameters",
        "Test for command injection in every input",
        "Analyse API endpoints for authentication flaws",
        "Check for GraphQL introspection and injection",
        "Test for CORS misconfiguration",
    ],
    "crypto": [
        "Identify cipher type (Caesar, Vigenere, RSA, AES, XOR)",
        "Look for weak RSA: small e, common modulus, Wiener's attack",
        "Try frequency analysis for substitution ciphers",
        "Check for padding oracle attacks (CBC mode)",
        "Test hash length extension attacks with hashpump",
        "Try factoring small RSA moduli with factordb",
        "Look for reused nonces in AES-CTR",
        "Check for ECB mode (identical ciphertext blocks)",
        "Try known-plaintext attacks",
        "Identify encoding: base64, base32, hex, rot13",
        "Test for stream cipher key reuse",
        "Look for timing side-channels",
    ],
    "pwn": [
        "Run checksec to identify protections (ASLR, NX, PIE, Canary)",
        "Find input length and overflow offset with pattern_create",
        "Identify memory corruption: BOF, UAF, format string",
        "Leak stack canary via format string (%p, %x)",
        "Find useful gadgets with ropper/ROPgadget",
        "Identify libc version with leaked addresses + libc-database",
        "Build ROP chain: ret2plt → ret2libc → one_gadget",
        "For SROP: find syscall gadget and craft sigreturn frame",
        "For heap: analyse allocator behaviour (tcache, fastbin)",
        "Heap exploitation: tcache poisoning, fastbin dup, house-of-force",
        "Use pwntools for exploit scripting and automation",
        "Test off-by-one and off-by-null bugs",
        "Look for format string exploits (%n for arbitrary write)",
    ],
    "forensics": [
        "Run 'file' to identify file type regardless of extension",
        "Check file headers with xxd/hexdump",
        "Extract embedded files with binwalk -e",
        "Check image metadata with exiftool",
        "Run strings to find hidden text",
        "Analyse PCAP with tshark/wireshark",
        "Check for steganography (steghide, stegsolve, zsteg)",
        "Analyse memory dump with volatility3",
        "Extract deleted files with foremost/photorec",
        "Look in PNG chunk data with pngcheck",
        "Check audio spectrograms in Audacity or Sonic Visualizer",
        "Search for flags in slack space or file system artifacts",
        "Analyse ZIP/archive structure for hidden data",
        "Check for polyglot files (valid as multiple formats)",
    ],
    "rev": [
        "Run 'file' and 'checksec' on the binary",
        "Disassemble main() with ghidra/radare2/objdump",
        "Run 'strings' to find hardcoded flags or keys",
        "Use ltrace/strace to trace library/system calls",
        "Identify obfuscation: XOR, base64, custom encoding",
        "Look for comparison operations near flag check",
        "Set breakpoints at strcmp/memcmp with gdb",
        "Use angr for symbolic execution of complex checks",
        "Patch binary to bypass checks (nop out conditional jumps)",
        "Decompile with ghidra and rename variables",
        "Look for anti-debugging tricks (ptrace, timing checks)",
        "Test with empty/known inputs and observe behaviour",
    ],
    "misc": [
        "Read the challenge description carefully for hints",
        "Try common encodings: base64, hex, rot13, morse",
        "Look for patterns and patterns-within-patterns",
        "Check whitespace: steganography in spaces/tabs",
        "Try QR code scanning if image is provided",
        "Google unique strings or error messages",
        "Look for braille, semaphore, or other encodings",
    ],
    "osint": [
        "Search target name on all social media",
        "Enumerate subdomains and cloud assets",
        "Check certificate transparency logs (crt.sh)",
        "Search Shodan/Censys for exposed services",
        "Google dorking: site: filetype: inurl:",
        "Check Wayback Machine for historical content",
        "WHOIS and DNS history lookup",
        "Check GitHub for leaked credentials or code",
        "LinkedIn for employee enumeration",
        "Check for exposed S3 buckets or cloud storage",
    ],
}

# ─── Workflow Steps per Category ──────────────────────────────────────────────

CATEGORY_WORKFLOWS: dict[str, list[dict[str, str]]] = {
    "web": [
        {"tool": "gobuster",   "goal": "enumerate directories and files",   "condition": "always"},
        {"tool": "nikto",      "goal": "scan for common web vulnerabilities", "condition": "always"},
        {"tool": "sqlmap",     "goal": "test for SQL injection",             "condition": "if forms found"},
        {"tool": "dalfox",     "goal": "scan for XSS vulnerabilities",       "condition": "if reflection found"},
        {"tool": "ffuf",       "goal": "fuzz parameters and endpoints",      "condition": "always"},
        {"tool": "nuclei",     "goal": "run vulnerability templates",        "condition": "always"},
    ],
    "pwn": [
        {"tool": "checksec",   "goal": "identify binary protections",        "condition": "always"},
        {"tool": "strings",    "goal": "extract strings from binary",        "condition": "always"},
        {"tool": "radare2",    "goal": "static analysis and disassembly",    "condition": "always"},
        {"tool": "gdb",        "goal": "dynamic analysis and exploitation",  "condition": "always"},
        {"tool": "pwntools",   "goal": "craft and send exploit",             "condition": "if vulnerability found"},
    ],
    "forensics": [
        {"tool": "file",       "goal": "identify file type",                 "condition": "always"},
        {"tool": "strings",    "goal": "extract printable strings",          "condition": "always"},
        {"tool": "binwalk",    "goal": "extract embedded files",             "condition": "always"},
        {"tool": "exiftool",   "goal": "read file metadata",                 "condition": "if image or media"},
        {"tool": "xxd",        "goal": "hexdump file for hidden data",       "condition": "always"},
    ],
    "rev": [
        {"tool": "file",       "goal": "identify binary format and arch",    "condition": "always"},
        {"tool": "strings",    "goal": "find hardcoded values and keys",     "condition": "always"},
        {"tool": "radare2",    "goal": "disassemble and decompile binary",   "condition": "always"},
        {"tool": "gdb",        "goal": "dynamic runtime analysis",           "condition": "always"},
    ],
    "crypto": [
        {"tool": "hashcat",    "goal": "crack hashes with wordlist",         "condition": "if hash found"},
        {"tool": "john",       "goal": "crack hashes with rules",            "condition": "if hash found"},
        {"tool": "hashpump",   "goal": "test hash length extension attack",  "condition": "if MAC present"},
    ],
    "osint": [
        {"tool": "theharvester", "goal": "gather emails and subdomains",    "condition": "always"},
        {"tool": "subfinder",  "goal": "enumerate subdomains",               "condition": "if domain given"},
        {"tool": "sherlock",   "goal": "find social media accounts",         "condition": "if username given"},
    ],
}

# ─── Flag Extraction Patterns ─────────────────────────────────────────────────

FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"[A-Z]{2,8}\{[A-Za-z0-9_\-]+\}",
    r"[A-Z]{2,8}\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"THM\{[^}]+\}",
    r"DUCTF\{[^}]+\}",
    r"[A-Za-z]{3,8}\{[A-Fa-f0-9]{32,}\}",
]


# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class CTFChallenge:
    name:        str
    category:    str
    description: str = ""
    points:      int = 0
    files:       list[str] = field(default_factory=list)
    url:         str = ""
    hints:       list[str] = field(default_factory=list)


@dataclass
class CTFSolveStrategy:
    challenge:   CTFChallenge
    category:    str
    strategies:  list[str]
    workflow:    list[dict[str, str]]
    tools:       list[str]
    time_est:    float   # minutes
    difficulty:  str     # easy / medium / hard


# ─── CTF Tool Manager ────────────────────────────────────────────────────────

class CTFToolManager:

    def suggest_tools(self, category: str, description: str = "") -> list[str]:
        """Return prioritised tool list for a category, refined by description keywords."""
        base = list(CATEGORY_TOOLS.get(category.lower(), CATEGORY_TOOLS["misc"]))

        keyword_tools: dict[str, list[str]] = {
            "sql":         ["sqlmap"],
            "xss":         ["dalfox", "xsser"],
            "upload":      ["gobuster", "ffuf"],
            "jwt":         ["jwt-analyzer"],
            "hash":        ["hashcat", "john"],
            "rsa":         ["python3"],
            "buffer":      ["pwntools", "gdb", "radare2"],
            "heap":        ["pwntools", "gdb"],
            "format":      ["pwntools", "gdb"],
            "pcap":        ["wireshark", "tshark"],
            "memory":      ["volatility3"],
            "steg":        ["steghide", "stegsolve", "zsteg"],
            "image":       ["exiftool", "binwalk", "file"],
            "wordpress":   ["wpscan"],
            "graphql":     ["graphql-scanner"],
            "api":         ["arjun", "ffuf", "httpx"],
            "crypto":      ["hashcat", "john", "python3"],
            "php":         ["php", "webshell"],
            "binary":      ["gdb", "radare2", "pwntools"],
        }

        desc_lower = description.lower()
        priority: list[str] = []
        for keyword, tools in keyword_tools.items():
            if keyword in desc_lower:
                for t in tools:
                    if t not in priority:
                        priority.append(t)

        # Merge: prioritised tools first, then base
        merged = priority + [t for t in base if t not in priority]
        return merged[:10]

    def get_tool_command(self, tool: str, target: str, category: str) -> str | None:
        """Return a default command template for the tool in CTF context."""
        commands: dict[str, str] = {
            "gobuster":    f"gobuster dir -u {target} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,txt,js",
            "ffuf":        f"ffuf -u {target}/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt -mc 200,301,302,403",
            "nikto":       f"nikto -h {target}",
            "sqlmap":      f"sqlmap -u '{target}' --batch --forms --level=3 --risk=2",
            "dalfox":      f"dalfox url {target} --skip-bav",
            "nuclei":      f"nuclei -u {target} -severity critical,high,medium",
            "strings":     f"strings {target} | grep -iE 'flag|key|pass|secret|cred'",
            "binwalk":     f"binwalk -e {target}",
            "exiftool":    f"exiftool {target}",
            "file":        f"file {target}",
            "xxd":         f"xxd {target} | head -50",
            "checksec":    f"checksec --file={target}",
            "radare2":     f"radare2 -A -q -c 'pdf @main' {target}",
            "gdb":         f"gdb -q {target}",
            "pwntools":    f"python3 -c \"from pwn import *; p = process('{target}'); p.interactive()\"",
            "hashcat":     f"hashcat -a 0 -m 0 {target} /usr/share/wordlists/rockyou.txt",
            "john":        f"john --wordlist=/usr/share/wordlists/rockyou.txt {target}",
            "hashpump":    f"hashpump -s '' -d '' -a '' -k 16",
            "steghide":    f"steghide info {target}",
            "tshark":      f"tshark -r {target} -Y 'http' -T fields -e http.request.uri -e http.file_data",
            "volatility3": f"python3 /opt/volatility3/vol.py -f {target} windows.info",
            "theharvester":f"theharvester -d {target} -b all",
            "subfinder":   f"subfinder -d {target} -all",
            "sherlock":    f"sherlock {target}",
        }
        return commands.get(tool)


# ─── CTF Workflow Manager ────────────────────────────────────────────────────

class CTFWorkflowManager:

    def __init__(self) -> None:
        self.tool_manager = CTFToolManager()

    def create_strategy(self, challenge: CTFChallenge) -> CTFSolveStrategy:
        cat = challenge.category.lower()
        strategies = CATEGORY_STRATEGIES.get(cat, CATEGORY_STRATEGIES["misc"])
        workflow    = CATEGORY_WORKFLOWS.get(cat, [])
        tools       = self.tool_manager.suggest_tools(cat, challenge.description)
        time_est    = self._estimate_time(cat, challenge.points)
        difficulty  = self._estimate_difficulty(challenge.points)

        return CTFSolveStrategy(
            challenge=challenge,
            category=cat,
            strategies=strategies,
            workflow=workflow,
            tools=tools,
            time_est=time_est,
            difficulty=difficulty,
        )

    def _estimate_time(self, category: str, points: int) -> float:
        base_times = {"web": 30, "crypto": 45, "pwn": 90, "forensics": 20, "rev": 60, "misc": 15, "osint": 25}
        base = base_times.get(category, 30)
        multiplier = 1 + (points / 500)
        return round(base * multiplier, 1)

    def _estimate_difficulty(self, points: int) -> str:
        if points <= 100:  return "easy"
        if points <= 300:  return "medium"
        return "hard"

    def generate_team_strategy(self, challenges: list[CTFChallenge]) -> dict[str, Any]:
        """Distribute challenges across team members by category and difficulty."""
        by_category: dict[str, list[CTFChallenge]] = {}
        for c in challenges:
            by_category.setdefault(c.category, []).append(c)

        # Sort by points descending (highest value first)
        for cat in by_category:
            by_category[cat].sort(key=lambda x: x.points, reverse=True)

        total_points = sum(c.points for c in challenges)
        return {
            "total_challenges": len(challenges),
            "total_points":     total_points,
            "by_category":      {cat: [c.name for c in chals] for cat, chals in by_category.items()},
            "priority_order":   sorted(by_category.keys(), key=lambda k: sum(c.points for c in by_category[k]), reverse=True),
            "efficiency_tip":   "Focus high-skill players on pwn/crypto; use web players for web/osint",
        }

    def to_dict(self, strategy: CTFSolveStrategy) -> dict[str, Any]:
        return {
            "challenge":    strategy.challenge.name,
            "category":     strategy.category,
            "difficulty":   strategy.difficulty,
            "time_est_min": strategy.time_est,
            "tools":        strategy.tools,
            "strategies":   strategy.strategies[:8],
            "workflow":     strategy.workflow,
        }


# ─── CTF Challenge Auto-Solver ────────────────────────────────────────────────

class CTFChallengeAutomator:

    def extract_flags(self, text: str) -> list[str]:
        """Extract all flag-like strings from output."""
        flags: list[str] = []
        for pattern in FLAG_PATTERNS:
            found = re.findall(pattern, text, re.IGNORECASE)
            for f in found:
                if f not in flags:
                    flags.append(f)
        return flags

    def generate_auto_solve_plan(self, challenge: CTFChallenge) -> dict[str, Any]:
        """Generate an automated solving plan with sequential and parallel steps."""
        cat     = challenge.category.lower()
        manager = CTFWorkflowManager()
        strategy = manager.create_strategy(challenge)

        parallel_steps = []
        sequential_steps = []

        # Recon-type steps can run in parallel
        parallel_categories = {"web", "osint"}
        if cat in parallel_categories and len(strategy.workflow) > 2:
            parallel_steps = strategy.workflow[:2]
            sequential_steps = strategy.workflow[2:]
        else:
            sequential_steps = strategy.workflow

        return {
            "challenge":        challenge.name,
            "category":         cat,
            "auto_approach":    "parallel_then_sequential" if parallel_steps else "sequential",
            "parallel_steps":   parallel_steps,
            "sequential_steps": sequential_steps,
            "flag_patterns":    FLAG_PATTERNS[:5],
            "manual_hints":     strategy.strategies[:3],
            "tools_needed":     strategy.tools[:5],
            "estimated_minutes": strategy.time_est,
        }

    def analyze_output_for_flag(self, output: str, challenge_name: str = "") -> dict[str, Any]:
        """Check tool output for flags and clues."""
        flags = self.extract_flags(output)
        clues: list[str] = []

        # Look for common CTF clues
        clue_patterns = {
            "Base64": r"[A-Za-z0-9+/]{20,}={0,2}",
            "Hex string": r"(?:0x)?[A-Fa-f0-9]{16,}",
            "JWT token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "Hash (MD5)": r"[a-f0-9]{32}",
            "Hash (SHA256)": r"[a-f0-9]{64}",
            "URL path": r"/[a-zA-Z0-9_\-/]+\?[^\"'\s]+",
            "Password-like": r"(?:pass(?:word)?|key|secret)[=:]\s*[\"']?([^\s\"']+)",
        }

        for name, pattern in clue_patterns.items():
            if re.search(pattern, output):
                clues.append(f"Found potential {name}")

        return {
            "flags_found":  flags,
            "flag_count":   len(flags),
            "clues":        clues,
            "solved":       len(flags) > 0,
            "output_size":  len(output),
        }
