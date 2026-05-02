import re
from dataclasses import dataclass

from core.context import SessionContext
from safety.scope import ScopeViolation, find_scope_violations
from tools.registry import get_tool


READ_ONLY_BLOCKED_CATEGORIES = {
    "active_directory",
    "exploitation",
    "passwords",
    "post_exploitation",
    "social_engineering",
    "sniffing",
    "wireless",
}

DANGEROUS_PATTERNS = [
    r"\brm\s+-[^\n]*r",
    r"\bchmod\s+777\b",
    r"\bmkfs\b",
    r"\bdd\s+if=",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bmsfconsole\b",
    r"\bmsfvenom\b",
    r"\bsqlmap\b.*\b(?:--dump|--os-shell|--file-write|--risk[=\s]*[23])\b",
    r"\bhydra\b",
    r"\bmedusa\b",
    r"\bncrack\b",
    r"\bhashcat\b",
    r"\bjohn(?:\s|$)",
    r"\bettercap\b",
    r"\barpspoof\b",
    r"\bmitm6\b",
    r"\baircrack-ng\b",
    r"\bwifite\b",
    r"\breaver\b",
    r"\bsetoolkit\b",
]

READ_ONLY_BLOCK_PATTERNS = DANGEROUS_PATTERNS + [
    r"\b(?:-X|--request)\s*(?:POST|PUT|PATCH|DELETE)\b",
    r"\b(?:POST|PUT|PATCH|DELETE)\b",
    r"\b--data(?:-raw|-binary)?\b",
    r"\b--forms\b",
    r"\b--crawl\b",
    r"\bFUZZ\b",
]


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    dangerous: bool = False
    reason: str = ""
    violations: list[ScopeViolation] | None = None


class Guardian:
    def __init__(
        self,
        require_scope: bool = True,
        confirm_dangerous: bool = True,
        read_only_mode: bool = False,
    ):
        self.require_scope = require_scope
        self.confirm_dangerous = confirm_dangerous
        self.read_only_mode = read_only_mode

    def assess(
        self,
        command: str,
        tool: str,
        context: SessionContext,
        ai_dangerous: bool = False,
    ) -> GuardDecision:
        violations = []
        if self.require_scope:
            violations = find_scope_violations(command, context.scope)
            if violations:
                targets = ", ".join(v.target for v in violations)
                return GuardDecision(
                    allowed=False,
                    dangerous=True,
                    reason=f"out-of-scope target blocked: {targets}",
                    violations=violations,
                )

        registry_info = get_tool(tool)
        registry_dangerous = bool(registry_info.get("dangerous", False))
        category = registry_info.get("category", "")
        pattern_dangerous = _matches_any(command, DANGEROUS_PATTERNS)
        dangerous = ai_dangerous or registry_dangerous or pattern_dangerous

        if self.read_only_mode:
            read_only_blocked = (
                dangerous
                or category in READ_ONLY_BLOCKED_CATEGORIES
                or _matches_any(command, READ_ONLY_BLOCK_PATTERNS)
            )
            if read_only_blocked:
                return GuardDecision(
                    allowed=False,
                    dangerous=True,
                    reason="read-only mode blocks this command",
                    violations=violations,
                )

        return GuardDecision(allowed=True, dangerous=dangerous, violations=violations)


def _matches_any(command: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, command, re.IGNORECASE) for pattern in patterns)
