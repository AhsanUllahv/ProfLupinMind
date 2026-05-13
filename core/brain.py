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

    def reset(self):
        self.history.clear()
