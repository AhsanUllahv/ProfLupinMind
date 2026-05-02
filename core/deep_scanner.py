"""
Autonomous deep scanner: scan → AI-analyze → dig → repeat until converged.

Phase progression:
    recon → service_enum → vuln_scan → deep_dive

At each phase, findings from the previous phase drive what tools run next.
Stops when no new attack surface is discovered for MAX_EMPTY_ITERS rounds,
or when max_scans is reached.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)


@dataclass
class ScanTask:
    tool: str
    options: str
    reason: str
    phase: str          # recon | service_enum | vuln_scan | deep_dive
    priority: int = 5   # 1 = highest


@dataclass
class DeepScanReport:
    target: str
    session_id: str
    total_scans: int
    iterations: int
    phases_completed: list
    findings_count: int
    vulnerabilities: list
    attack_surface: dict
    duration: float
    scan_history: list


class DeepScanner:
    """
    Autonomous iterative scan engine.

    Usage (from mcp_server.py)::

        scanner = DeepScanner(brain=brain, max_scans=30)
        report  = await scanner.run(target, context, execute_tool_fn, session_id)
    """

    MAX_EMPTY_ITERS = 4

    def __init__(self, brain=None, max_scans: int = 30):
        self.brain = brain
        self.max_scans = max_scans
        self._seen: set[str] = set()   # "tool:options" keys already queued/run
        self._queue: list[ScanTask] = []

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(
        self,
        target: str,
        context,                                              # SessionContext
        execute_tool: Callable[..., Awaitable[dict]],        # run_kali_tool
        session_id: str = "",
        on_phase: Callable[[str], None] | None = None,
    ) -> DeepScanReport:
        start = time.time()
        scan_history: list[dict] = []
        scan_count = 0
        iteration = 0
        phases_done: list[str] = []
        prev_surface = 0
        empty_iters = 0

        self._seed_recon(target, context)

        while self._queue and scan_count < self.max_scans:
            iteration += 1
            self._queue.sort(key=lambda t: t.priority)
            task = self._queue.pop(0)

            key = f"{task.tool}:{task.options}"
            if key in self._seen:
                continue
            self._seen.add(key)

            if task.phase not in phases_done:
                phases_done.append(task.phase)
                if on_phase:
                    on_phase(task.phase)

            scan_count += 1
            logger.info(
                f"🔄 [{scan_count}/{self.max_scans}] Phase={task.phase} | "
                f"{task.tool} — {task.reason}"
            )

            result = await execute_tool(
                tool=task.tool,
                target=target,
                options=task.options,
                session_id=session_id,
            )

            if result.get("blocked"):
                logger.warning(f"⚠️  Blocked: {task.tool} — skipping")
                continue

            output  = result.get("output", "")
            command = result.get("command", f"{task.tool} {target}")

            scan_history.append({
                "iteration":     iteration,
                "phase":         task.phase,
                "tool":          task.tool,
                "reason":        task.reason,
                "exit_code":     result.get("exit_code"),
                "output_preview": output[:500],
            })

            # AI analysis (optional — falls back gracefully if brain=None)
            await self._analyze(task.tool, command, output, context)

            # Rule-based extraction (always runs, supplements AI)
            self._extract_ports(target, output, context)
            self._extract_urls(output, context)
            self._extract_cves(output, context)

            # Decide next tasks based on everything found so far
            for next_task in self._next_tasks(target, context, task.phase):
                self._enqueue(next_task)

            # Convergence check
            surface = (
                sum(len(v) for v in context.open_ports.values())
                + len(context.urls)
                + len(context.findings)
            )
            if surface > prev_surface:
                empty_iters = 0
                prev_surface = surface
            else:
                empty_iters += 1

            if empty_iters >= self.MAX_EMPTY_ITERS and iteration > 3:
                logger.info(
                    "✅ CONVERGENCE: no new attack surface for "
                    f"{self.MAX_EMPTY_ITERS} rounds — scan complete"
                )
                break

        duration = time.time() - start
        vulns = [
            {
                "detail":   f.detail,
                "type":     f.type,
                "severity": f.severity,
                "tool":     f.tool,
            }
            for f in context.findings
            if f.severity in ("CRITICAL", "HIGH", "MEDIUM")
        ]
        all_ports = [
            p
            for ports in context.open_ports.values()
            for p in ports
        ]
        return DeepScanReport(
            target=target,
            session_id=session_id,
            total_scans=scan_count,
            iterations=iteration,
            phases_completed=phases_done,
            findings_count=len(context.findings),
            vulnerabilities=vulns,
            attack_surface={
                "ports":       all_ports,
                "urls":        context.urls[:20],
                "services":    dict(list(context.services.items())[:20]),
                "cves":        context.cves[:20],
                "credentials": context.credentials[:10],
            },
            duration=duration,
            scan_history=scan_history,
        )

    # ── Initial seed tasks ────────────────────────────────────────────────────

    def _seed_recon(self, target: str, context) -> None:
        is_web = (
            target.startswith("http://")
            or target.startswith("https://")
            or "." in target.split("/")[0]
        )
        is_domain = is_web and not self._is_ip(target)

        self._enqueue(ScanTask(
            tool="nmap",
            options="-sV -sC -T4 --open -p-",
            reason="Full port + service detection",
            phase="recon",
            priority=1,
        ))
        self._enqueue(ScanTask(
            tool="httpx",
            options="",
            reason="Web server detection + tech fingerprint",
            phase="recon",
            priority=2,
        ))
        if is_domain:
            self._enqueue(ScanTask(
                tool="subfinder",
                options="",
                reason="Subdomain enumeration",
                phase="recon",
                priority=2,
            ))
        self._enqueue(ScanTask(
            tool="nuclei",
            options="-severity critical,high",
            reason="Quick critical/high nuclei scan",
            phase="recon",
            priority=3,
        ))

    # ── Next-task generation ──────────────────────────────────────────────────

    def _next_tasks(self, target: str, context, current_phase: str) -> list[ScanTask]:
        tasks: list[ScanTask] = []

        all_ports: set[str] = set()
        for ports in context.open_ports.values():
            for p in ports:
                all_ports.add(p.split("/")[0])  # strip "/tcp" if present

        def add(tool, opts, reason, phase, pri=5):
            tasks.append(ScanTask(tool=tool, options=opts, reason=reason, phase=phase, priority=pri))

        has_web  = bool(all_ports & {"80", "443", "8080", "8443", "8000", "8888", "3000", "5000"})
        has_smb  = bool(all_ports & {"139", "445"})
        has_ftp  = "21"    in all_ports
        has_ssh  = "22"    in all_ports
        has_dns  = "53"    in all_ports
        has_smtp = bool(all_ports & {"25", "465", "587"})
        has_mysql  = "3306"  in all_ports
        has_mssql  = "1433"  in all_ports
        has_pgsql  = "5432"  in all_ports
        has_rdp    = "3389"  in all_ports
        has_redis  = "6379"  in all_ports
        has_mongo  = "27017" in all_ports
        has_ldap   = bool(all_ports & {"389", "636"})

        # ── Web ──────────────────────────────────────────────────────────────
        if has_web and current_phase == "recon":
            add("gobuster", "dir -w /usr/share/wordlists/dirb/common.txt -t 50 -q",
                "Directory enumeration", "service_enum", 2)
            add("nikto", "-nointeractive",
                "Web vulnerability scan", "vuln_scan", 3)
            add("whatweb", "--log-brief=/dev/null",
                "Technology fingerprinting", "service_enum", 3)
            add("wafw00f", "",
                "WAF detection", "service_enum", 4)
            add("katana", "-depth 3 -silent",
                "Web crawl + link discovery", "service_enum", 4)

        if has_web and current_phase == "service_enum":
            add("nuclei", "-severity critical,high,medium -silent",
                "Full nuclei template scan", "vuln_scan", 2)
            add("feroxbuster", "-w /usr/share/wordlists/dirb/big.txt -t 50 --quiet",
                "Deep directory brute-force", "vuln_scan", 3)
            add("dalfox", "",
                "XSS scanning", "vuln_scan", 4)
            add("arjun", "",
                "Parameter discovery", "service_enum", 4)

        if has_web and current_phase == "vuln_scan":
            add("sqlmap", "--level=2 --risk=1 --batch --output-dir=/tmp/sqlmap",
                "SQL injection test", "deep_dive", 3)
            add("ffuf", "-w /usr/share/wordlists/dirb/big.txt -fc 404",
                "FFUF deep fuzzing", "deep_dive", 4)

        # ── SMB ──────────────────────────────────────────────────────────────
        if has_smb and current_phase == "recon":
            add("enum4linux", "",
                "SMB full enumeration", "service_enum", 2)
            add("smbmap", "",
                "SMB share mapping", "service_enum", 2)

        if has_smb and current_phase == "service_enum":
            add("nmap", "-p 445 --script=smb-vuln*",
                "SMB vulnerability check", "vuln_scan", 2)
            add("netexec", "smb --shares --users",
                "NetExec SMB enum", "vuln_scan", 2)

        # ── FTP ──────────────────────────────────────────────────────────────
        if has_ftp and current_phase in ("recon", "service_enum"):
            add("nmap", "-p 21 --script=ftp-anon,ftp-bounce,ftp-vuln*",
                "FTP vulnerability check", "service_enum", 3)

        # ── SSH ──────────────────────────────────────────────────────────────
        if has_ssh and current_phase == "service_enum":
            add("nmap", "-p 22 --script=ssh-auth-methods,ssh2-enum-algos",
                "SSH enumeration", "service_enum", 4)

        # ── DNS ──────────────────────────────────────────────────────────────
        if has_dns and current_phase == "recon":
            add("dnsenum", "",
                "DNS enumeration + zone transfer attempt", "service_enum", 3)
            add("nmap", "-p 53 --script=dns-zone-transfer,dns-brute",
                "DNS brute-force", "service_enum", 3)

        # ── SMTP ─────────────────────────────────────────────────────────────
        if has_smtp and current_phase in ("recon", "service_enum"):
            add("nmap", "-p 25 --script=smtp-commands,smtp-enum-users,smtp-vuln*",
                "SMTP user enumeration", "service_enum", 4)

        # ── Databases ────────────────────────────────────────────────────────
        if has_mysql and current_phase in ("recon", "service_enum"):
            add("nmap", "-p 3306 --script=mysql-info,mysql-enum,mysql-vuln*",
                "MySQL enumeration", "service_enum", 3)

        if has_mssql and current_phase in ("recon", "service_enum"):
            add("nmap", "-p 1433 --script=ms-sql-info,ms-sql-config,ms-sql-vuln*",
                "MSSQL enumeration", "service_enum", 3)

        if has_pgsql and current_phase in ("recon", "service_enum"):
            add("nmap", "-p 5432 --script=pgsql-brute",
                "PostgreSQL enumeration", "service_enum", 4)

        if has_redis and current_phase in ("recon", "service_enum"):
            add("nmap", "-p 6379 --script=redis-info",
                "Redis info", "service_enum", 3)

        if has_mongo and current_phase in ("recon", "service_enum"):
            add("nmap", "-p 27017 --script=mongodb-info,mongodb-databases",
                "MongoDB enumeration", "service_enum", 3)

        # ── RDP ──────────────────────────────────────────────────────────────
        if has_rdp and current_phase in ("recon", "service_enum"):
            add("nmap", "-p 3389 --script=rdp-enum-encryption,rdp-vuln*",
                "RDP enumeration", "service_enum", 3)

        # ── LDAP ─────────────────────────────────────────────────────────────
        if has_ldap and current_phase in ("recon", "service_enum"):
            add("nmap", "-p 389 --script=ldap-search,ldap-brute",
                "LDAP enumeration", "service_enum", 3)

        # ── CVE-based exploits ────────────────────────────────────────────────
        for cve in context.cves[:3]:
            add("searchsploit", cve,
                f"Exploit lookup for {cve}", "deep_dive", 4)

        # ── URL parameter testing ────────────────────────────────────────────
        if current_phase == "vuln_scan":
            for url in [u for u in context.urls[:3] if "?" in u]:
                tasks.append(ScanTask(
                    tool="sqlmap",
                    options=f"--url '{url}' --level=2 --risk=1 --batch",
                    reason=f"SQLi test on {url}",
                    phase="deep_dive",
                    priority=3,
                ))

        return tasks

    # ── AI analysis ───────────────────────────────────────────────────────────

    async def _analyze(self, tool: str, command: str, output: str, context) -> None:
        if not self.brain or not output.strip():
            return
        try:
            analysis = await self.brain.analyze_output(tool, command, output, context)
            for f in analysis.get("findings", []):
                context.add_finding(
                    tool=tool,
                    type=f.get("type", "unknown"),
                    detail=f.get("detail", ""),
                    severity=f.get("severity", "INFO"),
                )
            if analysis.get("summary"):
                logger.info(f"🧠 AI: {analysis['summary']}")
        except Exception as exc:
            logger.warning(f"AI analysis error: {exc}")

    # ── Regex-based extractors (always run) ───────────────────────────────────

    def _extract_ports(self, target: str, output: str, context) -> None:
        for m in re.finditer(r"(\d{1,5})/(tcp|udp)\s+open", output, re.IGNORECASE):
            context.add_port(target, m.group(1))

    def _extract_urls(self, output: str, context) -> None:
        for m in re.finditer(r"https?://[^\s\"'<>]+", output):
            context.add_url(m.group(0).rstrip(".,;)"))

    def _extract_cves(self, output: str, context) -> None:
        for m in re.finditer(r"CVE-\d{4}-\d+", output, re.IGNORECASE):
            context.add_cve(m.group(0).upper())

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _enqueue(self, task: ScanTask) -> None:
        key = f"{task.tool}:{task.options}"
        if key not in self._seen:
            self._queue.append(task)

    @staticmethod
    def _is_ip(target: str) -> bool:
        clean = (
            target.replace("http://", "")
                  .replace("https://", "")
                  .split("/")[0]
                  .split(":")[0]
        )
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean))
