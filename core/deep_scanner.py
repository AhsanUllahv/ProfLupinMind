"""
Agent-driven deep scanner for ProfLupinMind.

Design goal:
    Think first, execute one carefully selected tool, exhaust that tool deeply,
    summarize what it learned, then select the next tool from evidence.

This module intentionally avoids a fixed "run everything" pipeline.  It uses a
single-tool exploration loop with dead-end detection, confidence scoring,
hypothesis-based testing, finding prioritisation, and lightweight attack-chain
construction.
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

logger = logging.getLogger(__name__)


SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
WEB_PORTS = {"80", "443", "8080", "8443", "8000", "8888", "3000", "5000", "9000"}

_FEEDBACK_PATH = Path.home() / ".proflupinmind" / "tool_feedback.json"


class ToolFeedbackStore:
    """Persists per-tool effectiveness scores across runs so future scans prioritise proven tools."""

    def __init__(self, path: Path = _FEEDBACK_PATH) -> None:
        self._path = path
        self._data: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        try:
            if self._path.exists():
                return json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            pass
        return {}

    def priority_bonus(self, tool: str) -> int:
        """Return 0–3 bonus used to re-rank candidate tools based on historical usefulness."""
        entry = self._data.get(tool, {})
        runs = entry.get("runs", 0)
        if runs < 2:
            return 0
        useful_ratio = entry.get("useful_runs", 0) / runs
        avg_delta = entry.get("total_evidence_delta", 0) / runs
        if useful_ratio >= 0.75 and avg_delta >= 2:
            return 3
        if useful_ratio >= 0.5:
            return 2
        if useful_ratio >= 0.25:
            return 1
        return 0

    def record(self, summaries: list) -> None:
        """Update effectiveness scores from a completed scan's tool summaries."""
        for s in summaries:
            entry = self._data.setdefault(
                s.tool, {"runs": 0, "useful_runs": 0, "total_evidence_delta": 0}
            )
            entry["runs"] += 1
            if s.useful:
                entry["useful_runs"] += 1
            entry["total_evidence_delta"] += len(s.discoveries)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._data, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as exc:
            logger.debug("feedback store write failed: %s", exc)


@dataclass
class ScanTask:
    tool: str
    options: str
    reason: str
    phase: str = "agentic"
    priority: int = 5
    hypothesis: str = ""
    expected: str = ""
    confidence: float = 0.7
    strategy: str = "exploration"  # exploration | exploitation


@dataclass
class ToolProfile:
    name: str
    role: str
    good_at: list[str]
    avoid_when: list[str]
    exhaustion_limit: int = 3


@dataclass
class ToolSummary:
    tool: str
    commands: list[str] = field(default_factory=list)
    discoveries: list[str] = field(default_factory=list)
    reason_to_stop: str = ""
    useful: bool = False


@dataclass
class AgentDecision:
    phase: str
    known: str
    missing: str
    possible_directions: list[str]
    chosen_tool: str
    reason: str
    confidence: float
    strategy: str
    hypothesis: str


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
    tool_summaries: list = field(default_factory=list)
    vulnerability_chains: list = field(default_factory=list)
    attack_map: dict = field(default_factory=dict)
    stop_reason: str = ""
    final_analysis: dict = field(default_factory=dict)


class DeepScanner:
    """Single-tool-deep-loop scanner.

    The engine repeatedly:
      1. thinks about known state and missing evidence,
      2. chooses exactly one tool,
      3. runs multiple refined commands with that same tool,
      4. stops that tool when output has diminishing returns,
      5. updates memory and chooses the next tool.
    """

    MAX_EMPTY_TOOLS = 3

    TOOL_PROFILES: dict[str, ToolProfile] = {
        "subfinder": ToolProfile("subfinder", "subdomain discovery", ["finding subdomains", "expanding DNS surface"], ["raw IP targets"], 2),
        "nmap": ToolProfile("nmap", "service discovery", ["open ports", "service versions", "safe NSE checks"], ["large web crawling"], 4),
        "httpx": ToolProfile("httpx", "web probing", ["live web services", "titles", "status codes", "technology hints"], ["non-web targets"], 3),
        "whatweb": ToolProfile("whatweb", "web fingerprinting", ["CMS/framework/server identification"], ["no web service discovered"], 2),
        "wafw00f": ToolProfile("wafw00f", "WAF detection", ["WAF/CDN identification"], ["non-web targets"], 1),
        "gobuster": ToolProfile("gobuster", "content discovery", ["directories", "hidden files", "backup paths"], ["no HTTP service"], 3),
        "feroxbuster": ToolProfile("feroxbuster", "recursive content discovery", ["directories", "hidden files", "recursive web paths"], ["no HTTP service"], 3),
        "ffuf": ToolProfile("ffuf", "deep fuzzing", ["recursive content discovery", "parameterized paths"], ["no baseline web response"], 3),
        "katana": ToolProfile("katana", "web crawling", ["URLs", "parameters", "JS endpoints"], ["static/non-web targets"], 2),
        "nikto": ToolProfile("nikto", "web misconfiguration checks", ["dangerous files", "headers", "server issues"], ["modern WAF-heavy targets where noise is high"], 2),
        "nuclei": ToolProfile("nuclei", "template-based vulnerability checks", ["known CVEs", "exposures", "misconfigurations"], ["before target surface is known"], 3),
        "searchsploit": ToolProfile("searchsploit", "exploit intelligence lookup", ["mapping versions/CVEs to public exploit references"], ["no version or CVE evidence"], 2),
        "enum4linux": ToolProfile("enum4linux", "SMB enumeration", ["shares", "users", "domain info"], ["no SMB port"], 2),
        "smbmap": ToolProfile("smbmap", "SMB share mapping", ["permissions", "anonymous shares"], ["no SMB port"], 2),
    }

    def __init__(self, brain=None, max_scans: int = 30, max_tool_iterations: int = 4, execution_mode: str = "automatic"):
        self.brain = brain
        self.max_scans = max_scans
        self.max_tool_iterations = max(1, max_tool_iterations)
        self.execution_mode = execution_mode
        self._seen_commands: set[str] = set()
        self._used_tools: set[str] = set()
        self._tool_summaries: list[ToolSummary] = []
        self._dead_ends: list[str] = []
        self._attack_map: dict[str, Any] = {"services": {}, "web": [], "findings": [], "relationships": []}
        self._chains: list[dict[str, Any]] = []
        self._events_path = Path("proflupinmind.events.jsonl")
        self._feedback = ToolFeedbackStore()

    async def run(
        self,
        target: str,
        context,
        execute_tool: Callable[..., Awaitable[dict]],
        session_id: str = "",
        on_phase: Callable[[str], None] | None = None,
    ) -> DeepScanReport:
        start = time.time()
        total_scans = 0
        outer_iterations = 0
        empty_tools = 0
        scan_history: list[dict[str, Any]] = []
        phases_done: list[str] = []
        stop_reason = "max scans reached"

        while total_scans < self.max_scans:
            outer_iterations += 1
            decision = await self._think(target, context, outer_iterations)
            if decision.chosen_tool == "stop":
                stop_reason = decision.reason
                break

            phase_label = f"single_tool::{decision.chosen_tool}"
            if phase_label not in phases_done:
                phases_done.append(phase_label)
                if on_phase:
                    on_phase(phase_label)

            logger.info(
                "🧠 THINK: tool=%s confidence=%.2f strategy=%s hypothesis=%s",
                decision.chosen_tool, decision.confidence, decision.strategy, decision.hypothesis,
            )
            self._event("thinking", {
                "iteration": outer_iterations,
                "known": decision.known,
                "missing": decision.missing,
                "possible_directions": decision.possible_directions,
                "chosen_tool": decision.chosen_tool,
                "reason": decision.reason,
                "confidence": decision.confidence,
                "strategy": decision.strategy,
                "hypothesis": decision.hypothesis,
            })

            before_surface = self._surface_score(context)
            summary, scans_used = await self._run_single_tool_loop(
                target=target,
                context=context,
                execute_tool=execute_tool,
                session_id=session_id,
                decision=decision,
                scan_history=scan_history,
                remaining=self.max_scans - total_scans,
            )
            total_scans += scans_used
            self._tool_summaries.append(summary)
            self._used_tools.add(decision.chosen_tool)

            after_surface = self._surface_score(context)
            if after_surface <= before_surface:
                empty_tools += 1
                self._dead_ends.append(decision.chosen_tool)
            else:
                empty_tools = 0

            self._update_attack_map(target, context)
            await self._build_vulnerability_chains(context, target)

            if empty_tools >= self.MAX_EMPTY_TOOLS:
                stop_reason = f"diminishing returns: {empty_tools} tools produced no new meaningful evidence"
                break
            if self._major_surface_explored(context):
                stop_reason = "major attack surface explored and no higher-value tool remains"
                break

        # Persist tool effectiveness for future runs before returning.
        self._feedback.record(self._tool_summaries)

        tool_summaries_raw = [s.__dict__ for s in self._tool_summaries]
        final_analysis = await self._final_analysis_phase(target, context, tool_summaries_raw)

        duration = time.time() - start
        vulns = self._prioritized_vulnerabilities(context)
        return DeepScanReport(
            target=target,
            session_id=session_id,
            total_scans=total_scans,
            iterations=outer_iterations,
            phases_completed=phases_done,
            findings_count=len(context.findings),
            vulnerabilities=vulns,
            attack_surface=self._attack_surface(context),
            duration=duration,
            scan_history=scan_history,
            tool_summaries=tool_summaries_raw,
            vulnerability_chains=self._chains,
            attack_map=self._attack_map,
            stop_reason=stop_reason,
            final_analysis=final_analysis,
        )

    async def _think(self, target: str, context, iteration: int) -> AgentDecision:
        """Thinking phase: choose the next best single tool from evidence.

        Tries AI-driven selection first (Brain.think); falls back to the
        deterministic candidate-ordering logic if Brain is unavailable or fails.
        """
        known = self._known_summary(context)
        missing = self._missing_summary(target, context)
        ratio = self._strategy_ratio(iteration)
        candidates = self._candidate_tools(target, context, ratio)

        for used in list(self._used_tools):
            if used in candidates and not self._revisit_is_useful(used, context):
                candidates.remove(used)

        if not candidates:
            return AgentDecision("stop", known, missing, [], "stop", "no useful candidate tools remain", 1.0, "stop", "")

        strategy = "exploration" if ratio >= 0.5 else "exploitation"

        # AI-driven selection: ask the Brain to reason over candidates.
        # Only worth calling when there is a real choice (>1 candidate).
        if self.brain and len(candidates) > 1:
            try:
                ai = await self.brain.think(
                    target=target,
                    known=known,
                    missing=missing,
                    candidates=candidates,
                    used_tools=self._used_tools,
                    strategy=strategy,
                )
                chosen = ai.get("chosen_tool", "")
                if chosen in candidates:
                    logger.info("🧠 AI THINK: chose %s (confidence=%.2f) — %s", chosen, ai.get("confidence", 0), ai.get("reason", ""))
                    self._event("ai_think", {
                        "chosen_tool": chosen,
                        "confidence": ai.get("confidence"),
                        "hypothesis": ai.get("hypothesis"),
                        "reason": ai.get("reason"),
                        "possible_directions": ai.get("possible_directions", []),
                    })
                    return AgentDecision(
                        phase="thinking",
                        known=known,
                        missing=missing,
                        possible_directions=ai.get("possible_directions", []),
                        chosen_tool=chosen,
                        reason=ai.get("reason", self._tool_direction(chosen, context)),
                        confidence=float(ai.get("confidence", self._confidence_for(chosen, target, context))),
                        strategy=ai.get("strategy", strategy),
                        hypothesis=ai.get("hypothesis", self._hypothesis_for(chosen, context)),
                    )
                logger.warning("AI returned tool %r not in candidates %s — falling back", chosen, candidates)
            except Exception as exc:
                logger.warning("AI tool selection failed, using deterministic fallback: %s", exc)

        # Deterministic fallback.
        chosen = candidates[0]
        return AgentDecision(
            phase="thinking",
            known=known,
            missing=missing,
            possible_directions=[self._tool_direction(t, context) for t in candidates[:3]],
            chosen_tool=chosen,
            reason=self._tool_direction(chosen, context),
            confidence=self._confidence_for(chosen, target, context),
            strategy=strategy,
            hypothesis=self._hypothesis_for(chosen, context),
        )

    async def _run_single_tool_loop(
        self,
        target: str,
        context,
        execute_tool: Callable[..., Awaitable[dict]],
        session_id: str,
        decision: AgentDecision,
        scan_history: list[dict[str, Any]],
        remaining: int,
    ) -> tuple[ToolSummary, int]:
        """Action phase: run one tool repeatedly until Brain declares exhaustion.

        Flow each iteration:
          1. Execute current command.
          2. Brain.analyze_output() extracts findings from the result.
          3. Brain.decide_next_in_tool() decides: run another command with the
             SAME tool (with AI-chosen options) or declare the tool exhausted.
          4. Fall back to the next static variant when Brain is unavailable or
             returns a command already seen.
          5. Stagnant-round detection (2 consecutive no-new-evidence rounds)
             acts as a final safety net when Brain is not available.
        """
        tool = decision.chosen_tool
        profile = self.TOOL_PROFILES.get(tool, ToolProfile(tool, "custom tool", [], [], self.max_tool_iterations))
        limit = min(profile.exhaustion_limit, self.max_tool_iterations, remaining)
        commands: list[str] = []
        discoveries: list[str] = []
        scans_used = 0
        stagnant_rounds = 0

        # Seed: first unused static variant as the entry-point command.
        current_task = self._next_static_variant(tool, target, context, decision)
        if current_task is None:
            return ToolSummary(tool, commands, discoveries, "tool exhausted: no initial command variant available", False), 0

        for idx in range(1, limit + 1):
            command_key = f"{current_task.tool}:{current_task.options}"

            # Guard: skip if Brain suggested a command we already ran.
            if command_key in self._seen_commands:
                current_task = self._next_static_variant(tool, target, context, decision)
                if current_task is None:
                    break
                command_key = f"{current_task.tool}:{current_task.options}"

            self._seen_commands.add(command_key)

            before = self._surface_score(context)
            logger.info("⚡ ACT [%d/%d] %s: %s", idx, limit, tool, current_task.reason)
            self._event("action", {
                "tool": current_task.tool,
                "options": current_task.options,
                "reason": current_task.reason,
                "hypothesis": current_task.hypothesis,
                "confidence": current_task.confidence,
                "strategy": current_task.strategy,
            })

            result = await execute_tool(
                tool=current_task.tool, target=target,
                options=current_task.options, session_id=session_id,
            )
            scans_used += 1

            if result.get("blocked"):
                self._event("blocked", {
                    "tool": current_task.tool,
                    "command": result.get("command", ""),
                    "reason": result.get("reason", ""),
                })
                scan_history.append(self._history_row(current_task, result, decision, "blocked"))
                break

            output = result.get("output", "") or ""
            command = result.get("command", f"{current_task.tool} {current_task.options} {target}".strip())
            commands.append(command)

            # Extract findings from output (regex + structured parser).
            await self._analyze(current_task.tool, command, output, context)
            self._extract_all(target, output, context, current_task.tool)

            after = self._surface_score(context)
            delta = after - before
            if delta > 0:
                discoveries.append(f"{current_task.tool} added {delta} new evidence point(s)")
                stagnant_rounds = 0
            else:
                stagnant_rounds += 1

            status_note = "new_evidence" if delta > 0 else "no_new_evidence"
            self._event("result", {
                "tool": current_task.tool,
                "command": command,
                "status": result.get("status", status_note),
                "exit_code": result.get("exit_code"),
                "evidence_delta": delta,
                "parsed": result.get("parsed", {}),
            })
            scan_history.append(self._history_row(current_task, result, decision, status_note, delta))

            # Stagnant-round safety net (no Brain or last resort).
            if stagnant_rounds >= 2:
                reason = "dead-end detection: 2 consecutive rounds with no new evidence"
                self._event("exhausted", {"tool": tool, "reason": reason, "commands": commands})
                return ToolSummary(tool, commands, discoveries, reason, bool(discoveries)), scans_used

            # ── AI-driven next-command decision ──────────────────────────────
            if self.brain and idx < limit:
                try:
                    next_dec = await self.brain.decide_next_in_tool(
                        tool=tool,
                        target=target,
                        last_command=command,
                        output=output,
                        hypothesis=current_task.hypothesis or decision.hypothesis,
                        previous_commands=commands,
                        context=context,
                    )
                    action = next_dec.get("action", "")

                    if action == "exhausted":
                        reason = next_dec.get("reason", "AI declared tool exhausted")
                        logger.info("🧠 BRAIN EXHAUSTED %s — %s", tool, reason)
                        self._event("exhausted", {"tool": tool, "reason": reason, "commands": commands})
                        return ToolSummary(tool, commands, discoveries, reason, bool(discoveries)), scans_used

                    if action == "continue":
                        ai_opts = (next_dec.get("options") or "").strip()
                        ai_key = f"{tool}:{ai_opts}"
                        if ai_opts and ai_key not in self._seen_commands:
                            logger.info(
                                "🧠 BRAIN NEXT [%s]: %s — %s",
                                tool, ai_opts[:80], next_dec.get("reason", ""),
                            )
                            self._event("ai_next_command", {
                                "tool": tool,
                                "options": ai_opts,
                                "reason": next_dec.get("reason"),
                                "new_hypothesis": next_dec.get("new_hypothesis"),
                                "expected_new_evidence": next_dec.get("expected_new_evidence"),
                            })
                            current_task = ScanTask(
                                tool=tool,
                                options=ai_opts,
                                reason=next_dec.get("reason", "AI-suggested next command"),
                                phase="ai_driven",
                                hypothesis=next_dec.get("new_hypothesis") or current_task.hypothesis,
                                confidence=decision.confidence,
                                strategy=decision.strategy,
                            )
                            continue
                        # AI suggested a duplicate — fall through to static.

                except Exception as exc:
                    logger.warning("Brain.decide_next_in_tool failed: %s", exc)

            # ── Static fallback: recompute with fresh context ─────────────────
            next_task = self._next_static_variant(tool, target, context, decision)
            if next_task is None:
                break
            current_task = next_task

        reason = "all relevant variants tried" if scans_used else "no executable variant remained"
        return ToolSummary(tool, commands, discoveries, reason, bool(discoveries)), scans_used

    def _next_static_variant(self, tool: str, target: str, context, decision: AgentDecision) -> "ScanTask | None":
        """Return the next unused static command variant for a tool, recomputing with current context."""
        for sv in self._command_variants(tool, target, context, decision):
            key = f"{sv.tool}:{sv.options}"
            if key not in self._seen_commands:
                return sv
        return None

    async def _final_analysis_phase(self, target: str, context, tool_summaries_raw: list[dict]) -> dict:
        """Ask Brain for a final narrative synthesis after all tools are exhausted."""
        if not self.brain:
            return {}
        try:
            result = await self.brain.final_analysis(
                target=target,
                context=context,
                tool_summaries=tool_summaries_raw,
                chains=self._chains,
            )
            logger.info(
                "🧠 FINAL ANALYSIS: exploitability=%s top_risks=%d gaps=%d",
                result.get("overall_exploitability", "?"),
                len(result.get("top_risks", [])),
                len(result.get("assessment_gaps", [])),
            )
            self._event("final_analysis", result)
            return result
        except Exception as exc:
            logger.warning("Final analysis phase failed: %s", exc)
            return {}

    def _candidate_tools(self, target: str, context, exploration_ratio: float) -> list[str]:
        ports = self._all_ports(context)
        has_web = bool(ports & WEB_PORTS) or target.startswith(("http://", "https://"))
        is_domain = self._is_domain(target)
        has_smb = bool(ports & {"139", "445"})

        exploration: list[str] = []
        exploitation: list[str] = []

        if is_domain and "subfinder" not in self._used_tools:
            exploration.append("subfinder")
        if "nmap" not in self._used_tools:
            exploration.append("nmap")
        if has_web:
            exploration.extend(["httpx", "whatweb", "katana"])
            exploitation.extend(["feroxbuster", "nikto", "nuclei", "ffuf", "wafw00f"])
        if has_smb:
            exploitation.extend(["enum4linux", "smbmap"])
        if context.cves:
            exploitation.append("searchsploit")
        if any("parameter" in f.type.lower() or "?" in f.detail for f in context.findings):
            exploitation.extend(["nuclei", "ffuf"])

        # Prioritize critical chain potential.
        if self._has_sensitive_lead(context):
            exploitation = ["nuclei", "nikto", "feroxbuster", "ffuf"] + exploitation

        ordered = exploration + exploitation if exploration_ratio >= 0.5 else exploitation + exploration
        deduped: list[str] = []
        for tool in ordered:
            if tool not in deduped and tool not in self._dead_ends:
                deduped.append(tool)

        # Stable-sort by feedback bonus so historically useful tools float up
        # without disrupting the exploration/exploitation ordering for ties.
        deduped.sort(key=lambda t: -self._feedback.priority_bonus(t))
        return deduped

    def _command_variants(self, tool: str, target: str, context, decision: AgentDecision) -> list[ScanTask]:
        ports = sorted(self._all_ports(context), key=lambda p: int(p) if p.isdigit() else 99999)
        port_csv = ",".join(ports) if ports else ""
        web_paths = self._interesting_paths(context)

        def task(opts: str, reason: str, confidence: float | None = None) -> ScanTask:
            return ScanTask(tool, opts, reason, "single_tool", 1, decision.hypothesis, decision.reason, confidence or decision.confidence, decision.strategy)

        if tool == "subfinder":
            return [task("-silent", "baseline subdomain discovery"), task("-all -recursive -silent", "deeper passive subdomain expansion")]
        if tool == "nmap":
            variants = [task("-sV -sC -T4 --open -p-", "full TCP service and version discovery")]
            if port_csv:
                variants.append(task(f"-sV -sC -p {port_csv} --script vuln", "safe vulnerability scripts against discovered services"))
                variants.append(task(f"-p {port_csv} -A --version-all", "deeper fingerprinting on confirmed open ports"))
            return variants
        if tool == "httpx":
            return [
                task("-title -tech-detect -status-code -follow-redirects -silent", "identify live web services and technologies"),
                task("-headers -status-code -title -silent", "inspect headers and response metadata"),
                task("-path /,/robots.txt,/sitemap.xml -status-code -title -silent", "check common discovery files"),
            ]
        if tool == "whatweb":
            return [task("--log-brief=/dev/null", "baseline web fingerprinting"), task("-a 3 --log-brief=/dev/null", "aggressive technology fingerprinting")]
        if tool == "wafw00f":
            return [task("", "detect WAF/CDN protection before heavier web testing")]
        if tool == "katana":
            return [task("-depth 2 -silent", "crawl visible links"), task("-depth 3 -js-crawl -silent", "crawl JavaScript-discovered endpoints")]
        if tool == "gobuster":
            variants = [
                task("dir -w /usr/share/wordlists/dirb/common.txt -t 40 -q -x php,txt,bak,old,zip", "discover common directories and sensitive extensions"),
                task("dir -w /usr/share/wordlists/dirb/big.txt -t 50 -q -x php,txt,bak,old,zip,sql", "deeper directory and backup-file discovery"),
            ]
            for path in web_paths[:2]:
                variants.append(task(f"dir -u {path} -w /usr/share/wordlists/dirb/common.txt -t 30 -q", f"dig inside discovered path {path}"))
            return variants
        if tool == "feroxbuster":
            base = self._web_base(target, context)
            variants = [
                task(f"-u {base} -w /usr/share/wordlists/dirb/common.txt -d 1 -t 10 -x php,html,js,txt,cgi --json -q", "recursive common web content discovery with clean JSON output"),
                task(f"-u {base} -w /usr/share/wordlists/dirb/big.txt -d 2 -t 10 -x php,html,js,txt,bak,old,zip --json -q", "deeper recursive discovery for backups and hidden paths"),
            ]
            for path in web_paths[:2]:
                variants.append(task(f"-u {path} -w /usr/share/wordlists/dirb/common.txt -d 1 -t 8 --json -q", f"dig inside discovered path {path}"))
            return variants
        if tool == "ffuf":
            base = self._web_base(target, context)
            return [
                task(f"-w /usr/share/wordlists/dirb/common.txt -u {base.rstrip('/')}/FUZZ -fc 404 -s", "fuzz baseline paths"),
                task(f"-w /usr/share/wordlists/dirb/big.txt -u {base.rstrip('/')}/FUZZ -fc 404 -recursion -recursion-depth 1 -s", "recursive deep content fuzzing"),
            ]
        if tool == "nikto":
            return [task("-nointeractive", "baseline web misconfiguration scan"), task("-Tuning x -nointeractive", "focus on interesting files and disclosure checks")]
        if tool == "nuclei":
            variants = [task("-severity critical,high,medium -silent", "template-based high-impact vulnerability checks")]
            if context.cves:
                variants.append(task(f"-id {','.join(context.cves[:5])} -silent", "CVE-focused nuclei verification"))
            variants.append(task("-tags exposure,misconfig,cve -silent", "exposure and misconfiguration templates"))
            return variants
        if tool == "searchsploit":
            terms = context.cves[:5] or list(context.services.values())[:3] or [target]
            return [task(str(term), f"lookup exploit intelligence for {term}") for term in terms]
        if tool == "enum4linux":
            return [task("-a", "full SMB enumeration"), task("-U -S -P", "SMB users, shares, and policy enumeration")]
        if tool == "smbmap":
            return [task("-u '' -p ''", "anonymous SMB share mapping"), task("-r", "recursive SMB share listing where allowed")]
        return [task("", f"baseline {tool} execution")]

    async def _analyze(self, tool: str, command: str, output: str, context) -> None:
        if not self.brain or not output.strip():
            return
        try:
            analysis = await self.brain.analyze_output(tool, command, output, context)
            for f in analysis.get("findings", []):
                context.add_finding(tool=tool, type=f.get("type", "unknown"), detail=f.get("detail", ""), severity=f.get("severity", "INFO"))
            if analysis.get("summary"):
                logger.info("🧠 AI ANALYSIS: %s", analysis["summary"])
        except Exception as exc:
            logger.warning("AI analysis error: %s", exc)

    def _extract_all(self, target: str, output: str, context, tool: str) -> None:
        self._extract_ports(target, output, context)
        self._extract_urls(output, context)
        self._extract_cves(output, context)
        self._extract_services(target, output, context)
        self._extract_findings(output, context, tool)
        self._extract_credentials(output, context)

    def _extract_ports(self, target: str, output: str, context) -> None:
        for m in re.finditer(r"(\d{1,5})/(tcp|udp)\s+open", output, re.IGNORECASE):
            context.add_port(target, m.group(1))

    def _extract_services(self, target: str, output: str, context) -> None:
        for m in re.finditer(r"(\d{1,5})/tcp\s+open\s+([^\s]+)\s*(.*)", output, re.IGNORECASE):
            port, svc, version = m.group(1), m.group(2), m.group(3).strip()
            context.add_service(f"{target}:{port}", f"{svc} {version}".strip())

    def _extract_urls(self, output: str, context) -> None:
        for m in re.finditer(r"https?://[^\s\"'<>]+", output):
            context.add_url(m.group(0).rstrip(".,;)"))

    def _extract_cves(self, output: str, context) -> None:
        for m in re.finditer(r"CVE-\d{4}-\d+", output, re.IGNORECASE):
            context.add_cve(m.group(0).upper())

    def _extract_credentials(self, output: str, context) -> None:
        patterns = [r"(?i)(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*([^\s'\"<>]{4,})"]
        for pat in patterns:
            for m in re.finditer(pat, output):
                cred = f"{m.group(1)}={m.group(2)}"
                if cred not in context.credentials:
                    context.credentials.append(cred)

    def _extract_findings(self, output: str, context, tool: str) -> None:
        checks = [
            (r"(?i)\.git/(HEAD|config|index)", "exposed_git_repository", "Exposed Git repository metadata discovered", "CRITICAL"),
            (r"(?i)(backup|\.bak|\.old|\.zip|\.sql|dump)", "backup_or_dump_file", "Potential backup/dump file exposure discovered", "HIGH"),
            (r"(?i)(directory indexing|index of /|parent directory)", "directory_listing", "Directory listing appears enabled", "HIGH"),
            (r"(?i)(admin|administrator|wp-admin|login)", "admin_surface", "Administrative or login surface discovered", "MEDIUM"),
            (r"(?i)(missing.*x-content-type-options|x-content-type-options.*not present)", "missing_security_header", "Missing X-Content-Type-Options header", "LOW"),
            (r"(?i)(strict-transport-security|HSTS).*not", "missing_hsts", "Missing or weak HSTS configuration", "LOW"),
            (r"(?i)(CVE-\d{4}-\d+)", "known_cve", "Known CVE reference discovered", "HIGH"),
            (r"(?i)(credential|password|secret|token|api[_-]?key)", "sensitive_data_indicator", "Sensitive data indicator found in output", "HIGH"),
        ]
        for pattern, ftype, detail, severity in checks:
            if re.search(pattern, output):
                context.add_finding(tool=tool, type=ftype, detail=detail, severity=severity)

    def _prioritized_vulnerabilities(self, context) -> list[dict[str, Any]]:
        rows = []
        for f in context.findings:
            if f.severity not in ("CRITICAL", "HIGH", "MEDIUM"):
                continue
            chain_bonus = 2 if self._finding_has_chain_potential(f) else 0
            sensitivity_bonus = 2 if re.search(r"(?i)(credential|token|secret|git|backup|dump|config)", f.detail + " " + f.type) else 0
            score = SEVERITY_RANK.get(f.severity, 1) * 10 + chain_bonus + sensitivity_bonus
            rows.append({"detail": f.detail, "type": f.type, "severity": f.severity, "tool": f.tool, "priority_score": score})
        return sorted(rows, key=lambda r: r["priority_score"], reverse=True)

    async def _build_vulnerability_chains(self, context, target: str = "") -> None:
        """Build vulnerability chains using static patterns plus AI reasoning.

        Static patterns provide reliable baseline chains. The AI layer adds
        escalation/bypass/pivot reasoning that the static rules cannot express.
        """
        findings = context.findings
        types = {f.type for f in findings}
        chains: list[dict[str, Any]] = []

        # Static patterns — always run, no API dependency.
        if {"exposed_git_repository", "sensitive_data_indicator"} & types and ("admin_surface" in types or context.credentials):
            chains.append({
                "name": "Source/config exposure to administrative access path",
                "impact": "Potential leakage of source code or secrets can support authentication bypass, credential reuse, or admin-panel access.",
                "steps": [f.type for f in findings if f.type in {"exposed_git_repository", "backup_or_dump_file", "sensitive_data_indicator", "admin_surface"}],
                "severity": "CRITICAL",
                "auth_bypass_potential": True,
                "pivot_potential": False,
                "data_exposure_potential": True,
            })
        if "backup_or_dump_file" in types and (context.credentials or "admin_surface" in types):
            chains.append({
                "name": "Backup disclosure to account compromise path",
                "impact": "Backup/dump exposure may reveal credentials or application internals that can be chained into authenticated access.",
                "steps": [f.type for f in findings if f.type in {"backup_or_dump_file", "sensitive_data_indicator", "admin_surface"}],
                "severity": "HIGH",
                "auth_bypass_potential": True,
                "pivot_potential": False,
                "data_exposure_potential": True,
            })
        if "directory_listing" in types and ("backup_or_dump_file" in types or "exposed_git_repository" in types):
            chains.append({
                "name": "Directory listing to sensitive file discovery",
                "impact": "Browsable directories can expose hidden sensitive files that would otherwise be difficult to locate.",
                "steps": [f.type for f in findings if f.type in {"directory_listing", "backup_or_dump_file", "exposed_git_repository"}],
                "severity": "HIGH",
                "auth_bypass_potential": False,
                "pivot_potential": False,
                "data_exposure_potential": True,
            })

        # AI-driven chain analysis — adds escalation/bypass/pivot reasoning.
        if self.brain and findings:
            try:
                ai_chains = await self.brain.analyze_chains(target or "target", context)
                if ai_chains:
                    logger.info("🧠 AI CHAINS: %d chain(s) identified", len(ai_chains))
                    chains.extend(ai_chains)
            except Exception as exc:
                logger.warning("AI chain analysis failed: %s", exc)

        self._chains = self._dedupe_chains(chains)

    def _update_attack_map(self, target: str, context) -> None:
        self._attack_map = {
            "target": target,
            "services": dict(context.services),
            "ports": self._all_ports_sorted(context),
            "web": context.urls[:50],
            "findings": [{"type": f.type, "severity": f.severity, "tool": f.tool, "detail": f.detail} for f in context.findings],
            "relationships": self._chains,
        }

    def _attack_surface(self, context) -> dict[str, Any]:
        return {
            "ports": self._all_ports_sorted(context),
            "urls": context.urls[:50],
            "services": dict(list(context.services.items())[:50]),
            "cves": context.cves[:50],
            "credentials": context.credentials[:10],
        }

    def _history_row(self, task: ScanTask, result: dict[str, Any], decision: AgentDecision, status_note: str, delta: int = 0) -> dict[str, Any]:
        output = result.get("output", "") or ""
        return {
            "tool": task.tool,
            "command": result.get("command", ""),
            "reason": task.reason,
            "hypothesis": task.hypothesis,
            "thinking": {
                "known": decision.known,
                "missing": decision.missing,
                "possible_directions": decision.possible_directions,
                "chosen_reason": decision.reason,
                "confidence": decision.confidence,
                "strategy": decision.strategy,
            },
            "exit_code": result.get("exit_code"),
            "status": result.get("status", status_note),
            "evidence_delta": delta,
            "output_preview": output[:700],
        }

    def _known_summary(self, context) -> str:
        return f"ports={self._all_ports_sorted(context)}, urls={len(context.urls)}, findings={len(context.findings)}, cves={len(context.cves)}, credentials={len(context.credentials)}"

    def _missing_summary(self, target: str, context) -> str:
        ports = self._all_ports(context)
        if not ports:
            return "open ports and service versions are unknown"
        if bool(ports & WEB_PORTS) and not context.urls:
            return "web endpoints and technologies are not mapped"
        if context.urls and not any(f.type in {"backup_or_dump_file", "exposed_git_repository", "directory_listing"} for f in context.findings):
            return "hidden content, exposure checks, and chainable weaknesses need validation"
        return "next useful missing item is exploitability/chaining evidence"

    def _strategy_ratio(self, iteration: int) -> float:
        if iteration <= 2:
            return 0.70
        if iteration <= 5:
            return 0.50
        return 0.30

    def _tool_direction(self, tool: str, context) -> str:
        profile = self.TOOL_PROFILES.get(tool)
        if not profile:
            return f"Use {tool} because it may add target-specific evidence."
        return f"Use {tool} for {profile.role}: {', '.join(profile.good_at[:2])}."

    def _hypothesis_for(self, tool: str, context) -> str:
        mapping = {
            "subfinder": "The domain may have additional subdomains that expand the attack surface.",
            "nmap": "The target may expose services whose versions reveal attack paths.",
            "httpx": "Discovered hosts/ports may expose live HTTP services with identifiable technologies.",
            "whatweb": "The web service may be a CMS/framework with known weak points.",
            "gobuster": "Hidden directories or backup files may exist under the web root.",
            "ffuf": "Recursive fuzzing may reveal deeper hidden content or parameters.",
            "katana": "Crawling may reveal URLs, JavaScript endpoints, and parameters.",
            "nikto": "The web server may expose misconfigurations or dangerous files.",
            "nuclei": "Known templates may validate high-impact exposures or CVEs.",
            "searchsploit": "Identified versions/CVEs may map to known public exploits.",
        }
        return mapping.get(tool, f"{tool} may validate a specific unknown in the current attack map.")

    def _confidence_for(self, tool: str, target: str, context) -> float:
        ports = self._all_ports(context)
        if tool == "nmap" and not ports:
            return 0.95
        if tool == "subfinder" and self._is_domain(target):
            return 0.90
        if tool in {"httpx", "whatweb", "gobuster", "ffuf", "katana", "nikto", "nuclei", "wafw00f"} and (ports & WEB_PORTS or target.startswith(("http://", "https://"))):
            return 0.85
        if tool == "searchsploit" and (context.cves or context.services):
            return 0.80
        return 0.60

    def _surface_score(self, context) -> int:
        return sum(len(v) for v in context.open_ports.values()) + len(context.urls) + len(context.findings) + len(context.cves) + len(context.credentials) + len(context.services)

    def _all_ports(self, context) -> set[str]:
        return {p.split("/")[0] for ports in context.open_ports.values() for p in ports}

    def _all_ports_sorted(self, context) -> list[str]:
        return sorted(self._all_ports(context), key=lambda p: int(p) if p.isdigit() else 99999)

    def _interesting_paths(self, context) -> list[str]:
        paths = []
        for url in context.urls:
            if re.search(r"(?i)(admin|backup|api|upload|config|repository|install)", url):
                paths.append(url)
        return paths

    def _has_sensitive_lead(self, context) -> bool:
        blob = " ".join(f.type + " " + f.detail for f in context.findings)
        return bool(re.search(r"(?i)(git|backup|dump|credential|secret|token|config|admin)", blob))

    def _finding_has_chain_potential(self, finding) -> bool:
        return bool(re.search(r"(?i)(git|backup|dump|credential|secret|token|config|admin|directory)", finding.type + " " + finding.detail))

    def _revisit_is_useful(self, tool: str, context) -> bool:
        if tool in {"nuclei", "searchsploit"} and context.cves:
            return True
        if tool in {"gobuster", "ffuf"} and self._has_sensitive_lead(context):
            return True
        return False

    def _major_surface_explored(self, context) -> bool:
        ports = self._all_ports(context)
        has_web = bool(ports & WEB_PORTS) or bool(context.urls)
        recon_done = "nmap" in self._used_tools
        # For web targets, do not stop after only fingerprinting. Require at
        # least one content-discovery tool and one vulnerability/exposure check.
        if has_web:
            content_done = bool({"gobuster", "feroxbuster", "ffuf", "katana"} & self._used_tools)
            vuln_done = bool({"nuclei", "nikto"} & self._used_tools)
            return recon_done and content_done and vuln_done and len(self._used_tools) >= 5 and not self._has_unexplored_high_value(context)
        return recon_done and len(self._used_tools) >= 2 and not self._has_unexplored_high_value(context)

    def _has_unexplored_high_value(self, context) -> bool:
        if context.cves and "searchsploit" not in self._used_tools:
            return True
        if self._has_sensitive_lead(context) and "nuclei" not in self._used_tools:
            return True
        return False

    def _dedupe_chains(self, chains: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        out = []
        for c in chains:
            key = (c["name"], tuple(c.get("steps", [])))
            if key not in seen:
                seen.add(key)
                out.append(c)
        return out

    def _web_base(self, target: str, context) -> str:
        if target.startswith(("http://", "https://")):
            return target.rstrip("/")
        ports = self._all_ports(context)
        if "443" in ports or "8443" in ports:
            return f"https://{target}"
        return f"http://{target}"

    def _event(self, phase: str, data: dict[str, Any]) -> None:
        row = {"ts": time.time(), "phase": phase, **data}
        try:
            with self._events_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception as exc:
            logger.debug("event log write failed: %s", exc)

    @staticmethod
    def _is_domain(target: str) -> bool:
        clean = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        return "." in clean and not DeepScanner._is_ip(clean)

    @staticmethod
    def _is_ip(target: str) -> bool:
        clean = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
        return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", clean))
