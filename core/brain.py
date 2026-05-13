import json
import re
from anthropic import AsyncAnthropic
from core.context import SessionContext
from tools.registry import get_tools_summary

_MAX_HISTORY = 20  # keep last 10 turns to prevent token overflow

# Static portion of the system prompt — pre-filled with the tool registry once
# at Brain.__init__ time and passed with cache_control so Anthropic caches it.
_STATIC_TEMPLATE = """You are an expert Kali Linux penetration tester with 15+ years of experience.
Your job is to help the user achieve their security testing goal by selecting the correct tools, building precise commands, analyzing output, and deciding the next logical step.

## AVAILABLE KALI TOOLS
{tools}

## STRICT RULES
- Only suggest commands relevant to the stated goal
- Separate thinking from acting: analyze evidence first, then choose exactly one command
- Prefer single-tool depth: refine the current tool until it stops producing meaningful new data before switching tools
- Always include a confidence score between 0.0 and 1.0 for command decisions
- Build and test hypotheses instead of blindly reacting to output
- Prioritize findings with sensitivity, exploit potential, access level, and chaining potential
- Detect dead ends: repeated/no-new output means the current path should be deprioritized
- Always set "dangerous": true for commands that could cause DoS, modify remote systems, or generate exploitation payloads
- Build complete, ready-to-run commands — no placeholders like <target>, use the actual target from context
- If the goal is fully achieved, set "action": "goal_complete"
- If you need more info from the user before proceeding, set "action": "ask_user"
- Never run the same command twice

## OUTPUT FORMAT
Respond ONLY with a single valid JSON object. No markdown, no explanation outside the JSON.

When running a command:
{{
  "action": "run_command",
  "tool": "<tool name from registry>",
  "command": "<complete shell command ready to execute>",
  "explanation": "<one sentence: what this command does and why>",
  "thinking": {
    "known": "<what is already known>",
    "missing": "<what is missing>",
    "hypothesis": "<hypothesis being tested>",
    "alternatives_considered": ["<direction 1>", "<direction 2>"]
  },
  "confidence": 0.0,
  "strategy": "exploration|exploitation",
  "dangerous": false
}}

When asking the user a question:
{{
  "action": "ask_user",
  "question": "<specific question>"
}}

When goal is complete:
{{
  "action": "goal_complete",
  "summary": "<plain English summary of everything that was accomplished and found>"
}}

When analyzing tool output, use this format:
{{
  "findings": [
    {{"type": "<e.g. open_port, vulnerability, service, url, credential>", "detail": "<specific detail>", "severity": "<CRITICAL|HIGH|MEDIUM|LOW|INFO>"}}
  ],
  "summary": "<2-3 sentences summarizing key findings>",
  "action": "run_command" | "ask_user" | "goal_complete",
  "tool": "<next tool if action is run_command>",
  "command": "<complete next command>",
  "explanation": "<why run this next>",
  "thinking": {
    "known": "<what the output proved>",
    "missing": "<what still needs testing>",
    "hypothesis": "<next hypothesis>",
    "tool_exhausted": false,
    "dead_end_detected": false,
    "chain_opportunities": ["<possible chain>" ]
  },
  "confidence": 0.0,
  "strategy": "exploration|exploitation",
  "dangerous": false
}}
"""

# Dynamic portion — per-call context injected as a separate (uncached) block.
_DYNAMIC_TEMPLATE = """## CURRENT SESSION STATE
{context}

## CVE INTELLIGENCE
{cve_context}
"""

# Tool-selection thinking prompt — lightweight, no history needed.
_THINK_TEMPLATE = """You are the reasoning brain of an AI-driven penetration tester.

## TARGET
{target}

## STRATEGY
{strategy}  (exploration = discover new attack surface | exploitation = dig into known findings)

## WHAT IS KNOWN
{known}

## WHAT IS MISSING
{missing}

## CANDIDATE TOOLS  (choose from this list only)
{candidates}

## ALREADY USED / EXHAUSTED
{used_tools}

Choose exactly ONE tool from the candidates list. Consider which tool closes the largest gap in knowledge given the current strategy.

Respond ONLY with valid JSON — no markdown, no explanation:
{{
  "chosen_tool": "<must be from candidates>",
  "confidence": 0.0,
  "hypothesis": "<one sentence: what this tool is expected to reveal>",
  "strategy": "exploration|exploitation",
  "reason": "<one sentence: why this tool over the others>",
  "possible_directions": ["<alt 1>", "<alt 2>", "<alt 3>"]
}}"""

# Vulnerability chain analysis prompt — reasons about escalation, bypass, pivot.
_CHAIN_TEMPLATE = """You are analyzing penetration testing findings to identify vulnerability chains.

A vulnerability chain is a sequence of issues that, when combined, creates a larger attack scenario.

## TARGET
{target}

## FINDINGS
{findings}

## SERVICES
{services}

## CREDENTIALS FOUND
{credentials}

For each chain you identify, reason about:
- Can this lead to data exposure?
- Can this escalate privileges?
- Can this bypass authentication?
- Can this pivot to another system?

Only include chains with at least two connected findings. Skip speculative chains where evidence is absent.

Respond ONLY with valid JSON — no markdown, no explanation:
{{
  "chains": [
    {{
      "name": "<descriptive chain name>",
      "severity": "CRITICAL|HIGH|MEDIUM",
      "steps": ["<finding type 1>", "<finding type 2>"],
      "impact": "<concrete impact — what an attacker achieves>",
      "escalation_path": "<how privileges or access are escalated, or 'none'>",
      "auth_bypass_potential": false,
      "pivot_potential": false,
      "data_exposure_potential": false
    }}
  ]
}}"""


# Prompt: decide whether to run another command with the SAME tool or declare it exhausted.
_NEXT_IN_TOOL_TEMPLATE = """You are controlling a single penetration testing tool and must decide the next command.

## TOOL IN USE
{tool}

## TARGET
{target}

## HYPOTHESIS BEING TESTED
{hypothesis}

## COMMANDS ALREADY RUN WITH THIS TOOL
{previous_commands}

## LAST COMMAND
{last_command}

## LAST OUTPUT (truncated to 3000 chars)
{output}

## CURRENT SESSION KNOWLEDGE
{context}

Your task: decide the NEXT action using this SAME tool only. Do not switch tools.

Ask yourself:
- Did the output reveal new hosts, subdomains, paths, parameters, ports, or services this tool can probe?
- Can refining flags (depth, wordlist, intensity, port range, extensions) extract genuinely new evidence?
- Have all meaningful variants been tried and are we only seeing duplicate or empty results?

Return "continue" with a SPECIFIC new options string if there is clear new evidence to pursue.
Return "exhausted" if this tool has extracted all the insight it can from this target.

Respond ONLY with valid JSON — no markdown, no explanation:
{{
  "action": "continue|exhausted",
  "options": "<just the flags/options part for the next command if continue, empty string if exhausted>",
  "reason": "<one sentence: specific justification — what new evidence this will reveal or why tool is done>",
  "new_hypothesis": "<updated hypothesis if continue, empty if exhausted>",
  "expected_new_evidence": "<what this next command is expected to reveal, empty if exhausted>"
}}"""

# Prompt: final synthesis after all tools are exhausted.
_FINAL_ANALYSIS_TEMPLATE = """You are a senior penetration tester writing the final analysis of a completed security assessment.

## TARGET
{target}

## TOOLS USED AND THEIR OUTCOMES
{tool_summaries}

## ALL FINDINGS
{findings}

## VULNERABILITY CHAINS IDENTIFIED
{chains}

## ATTACK SURFACE
Ports: {ports}
Services: {services}
Web endpoints discovered: {url_count}
CVEs identified: {cves}
Credential indicators found: {credential_count}

Synthesize a complete final assessment. Be specific and concrete — reference actual findings where possible.

Respond ONLY with valid JSON — no markdown, no explanation:
{{
  "executive_narrative": "<professional 3–5 sentence risk summary suitable for a non-technical stakeholder — state what was found and what risk it represents>",
  "methodology_narrative": "<2–3 sentences describing how the agent approached the target: what drove tool selection, what strategy was used, what was discovered along the way>",
  "top_risks": [
    {{
      "rank": 1,
      "title": "<concise risk title>",
      "why_critical": "<specific impact and exploitability reasoning based on the actual findings>",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW"
    }}
  ],
  "overall_exploitability": "trivial|easy|moderate|hard|very_hard",
  "exploitability_reasoning": "<two sentences explaining how easily an attacker could achieve meaningful impact based on discovered findings>",
  "assessment_gaps": ["<specific area not fully explored or tested>"],
  "recommended_next_steps": ["<specific actionable recommendation tied to a finding>"]
}}"""


class Brain:
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6"):
        self.client = AsyncAnthropic(api_key=api_key)
        self.model = model
        self.history = []
        # Pre-fill static prompt once; tools summary is also cached at registry level.
        self._static_prompt = _STATIC_TEMPLATE.format(tools=get_tools_summary())

    def _build_system_prompt(self, context: SessionContext) -> list[dict]:
        """Return a two-block system prompt: static (cached) + dynamic (per-call)."""
        cve_context = "No CVEs identified yet."
        if context.cves:
            cve_context = (
                f"{len(context.cves)} CVE(s) found: {', '.join(context.cves[:10])}\n"
                "Prioritise exploiting these in your recommendations."
            )
        dynamic = _DYNAMIC_TEMPLATE.format(
            context=context.to_string(),
            cve_context=cve_context,
        )
        return [
            {"type": "text", "text": self._static_prompt, "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": dynamic},
        ]

    def _parse_json(self, text: str) -> dict:
        text = text.strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # Strip markdown code fences if present
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        # Last resort: find the outermost { ... }
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group())
        raise ValueError(f"Could not parse JSON from AI response:\n{text}")

    async def generate_command(self, user_input: str, context: SessionContext) -> dict:
        """Turn natural language input into a command decision."""
        self.history.append({"role": "user", "content": user_input})

        response = await self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=self._build_system_prompt(context),
            messages=self.history[-_MAX_HISTORY:],
        )

        content = response.content[0].text
        self.history.append({"role": "assistant", "content": content})
        return self._parse_json(content)

    async def analyze_output(
        self,
        tool: str,
        command: str,
        output: str,
        context: SessionContext,
    ) -> dict:
        """Analyze tool output and decide the next step."""
        truncated = output[:4000] + ("\n...[output truncated]" if len(output) > 4000 else "")

        prompt = (
            f"The command `{command}` just finished.\n\n"
            f"OUTPUT:\n{truncated}\n\n"
            "Analyze this output:\n"
            "1. Extract all important findings (ports, services, vulnerabilities, URLs, credentials, CVEs)\n"
            "2. Summarize key results in 2-3 sentences\n"
            "3. Decide what to do next based on the original goal\n\n"
            "Respond using the analysis JSON format defined in your instructions."
        )

        self.history.append({"role": "user", "content": prompt})

        response = await self.client.messages.create(
            model=self.model,
            max_tokens=2048,
            system=self._build_system_prompt(context),
            messages=self.history[-_MAX_HISTORY:],
        )

        content = response.content[0].text
        self.history.append({"role": "assistant", "content": content})
        return self._parse_json(content)

    async def think(
        self,
        target: str,
        known: str,
        missing: str,
        candidates: list[str],
        used_tools: set[str],
        strategy: str,
    ) -> dict:
        """AI-driven tool selection: choose the next tool from current evidence."""
        prompt = _THINK_TEMPLATE.format(
            target=target,
            strategy=strategy,
            known=known,
            missing=missing,
            candidates="\n".join(f"- {t}" for t in candidates),
            used_tools=", ".join(sorted(used_tools)) if used_tools else "none yet",
        )
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=512,
            system=[{"type": "text", "text": self._static_prompt, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": prompt}],
        )
        return self._parse_json(response.content[0].text)

    async def analyze_chains(self, target: str, context) -> list[dict]:
        """AI-driven vulnerability chain analysis with escalation/bypass/pivot reasoning."""
        if not context.findings:
            return []
        findings_text = "\n".join(
            f"- [{f.severity}] {f.type}: {f.detail} (tool: {f.tool})"
            for f in context.findings
        )
        services_text = (
            "\n".join(f"- {k}: {v}" for k, v in list(context.services.items())[:20])
            or "none"
        )
        creds_text = f"{len(context.credentials)} credential(s) found" if context.credentials else "none"
        prompt = _CHAIN_TEMPLATE.format(
            target=target,
            findings=findings_text,
            services=services_text,
            credentials=creds_text,
        )
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=[{"type": "text", "text": self._static_prompt, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": prompt}],
        )
        result = self._parse_json(response.content[0].text)
        return result.get("chains", [])

    async def decide_next_in_tool(
        self,
        tool: str,
        target: str,
        last_command: str,
        output: str,
        hypothesis: str,
        previous_commands: list[str],
        context: SessionContext,
    ) -> dict:
        """Ask AI: given the last output, run another command with the SAME tool or declare exhaustion?"""
        truncated = output[:3000] + ("\n...[output truncated]" if len(output) > 3000 else "")
        prev = "\n".join(f"  - {c}" for c in previous_commands[-5:]) or "  none yet"
        prompt = _NEXT_IN_TOOL_TEMPLATE.format(
            tool=tool,
            target=target,
            hypothesis=hypothesis or "discover everything useful this tool can reveal",
            previous_commands=prev,
            last_command=last_command,
            output=truncated,
            context=context.to_string(),
        )
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=512,
            system=[{"type": "text", "text": self._static_prompt, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": prompt}],
        )
        return self._parse_json(response.content[0].text)

    async def final_analysis(
        self,
        target: str,
        context: SessionContext,
        tool_summaries: list[dict],
        chains: list[dict],
    ) -> dict:
        """Synthesize all findings into a final assessment narrative."""
        if not context.findings and not chains:
            return {}
        findings_text = "\n".join(
            f"  [{f.severity}] {f.type}: {f.detail} (tool: {f.tool})"
            for f in context.findings
        ) or "  none"
        chains_text = "\n".join(
            f"  [{c.get('severity','?')}] {c.get('name','?')}: {c.get('impact','')}"
            for c in chains[:10]
        ) or "  none"
        ts_text = "\n".join(
            f"  {s.get('tool','?')}: {len(s.get('commands',[]))} cmd(s), "
            f"{len(s.get('discoveries',[]))} discovery(ies) — {s.get('reason_to_stop','')}"
            for s in tool_summaries
        ) or "  none"
        all_ports = sorted({p for ports in context.open_ports.values() for p in ports})
        prompt = _FINAL_ANALYSIS_TEMPLATE.format(
            target=target,
            tool_summaries=ts_text,
            findings=findings_text,
            chains=chains_text,
            ports=", ".join(all_ports) or "none",
            services=", ".join(f"{k}: {v}" for k, v in list(context.services.items())[:10]) or "none",
            url_count=len(context.urls),
            cves=", ".join(context.cves[:10]) or "none",
            credential_count=len(context.credentials),
        )
        response = await self.client.messages.create(
            model=self.model,
            max_tokens=1500,
            system=[{"type": "text", "text": self._static_prompt, "cache_control": {"type": "ephemeral"}}],
            messages=[{"role": "user", "content": prompt}],
        )
        return self._parse_json(response.content[0].text)

    def reset(self):
        self.history.clear()
