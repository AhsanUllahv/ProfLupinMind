import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from sessions.manager import SessionManager
from sessions.models import CommandRecord, FindingRecord, PentestSession


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass(frozen=True)
class ReportResult:
    session_id: str
    markdown_path: Path
    html_path: Path
    pdf_path: Path | None = None


class ReportGenerator:
    def __init__(
        self,
        session_manager: SessionManager | None = None,
        template_dir: str | Path = "reports/templates",
        output_dir: str | Path = "reports/output",
    ):
        self.session_manager = session_manager or SessionManager()
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(enabled_extensions=("html", "xml")),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(self, session_id: str, include_pdf: bool = True) -> ReportResult:
        data = self._load_report_data(session_id)
        slug = _safe_slug(f"{data['session'].target}-{session_id}")

        markdown = self.env.get_template("report.md.j2").render(**data)
        html = self.env.get_template("report.html.j2").render(**data)

        markdown_path = self.output_dir / f"{slug}.md"
        html_path = self.output_dir / f"{slug}.html"
        markdown_path.write_text(markdown, encoding="utf-8")
        html_path.write_text(html, encoding="utf-8")

        pdf_path = None
        if include_pdf:
            pdf_path = self._write_pdf(html_path, slug)

        return ReportResult(
            session_id=session_id,
            markdown_path=markdown_path,
            html_path=html_path,
            pdf_path=pdf_path,
        )

    def _load_report_data(self, session_id: str) -> dict[str, Any]:
        with self.session_manager.SessionLocal() as db:
            session = db.get(PentestSession, session_id)
            if session is None:
                raise ValueError(f"Session not found: {session_id}")

            findings = (
                db.query(FindingRecord)
                .filter_by(session_id=session_id)
                .order_by(FindingRecord.id)
                .all()
            )
            commands = (
                db.query(CommandRecord)
                .filter_by(session_id=session_id)
                .order_by(CommandRecord.id)
                .all()
            )

            findings_data = [_finding_to_dict(f) for f in findings]
            commands_data = [_command_to_dict(c) for c in commands]
            severity_counts = _severity_counts(findings_data)
            grouped = _group_findings(findings_data)
            cves = _extract_cves(findings_data)

            # Extract scan-level metadata written by autonomous_deep_scan.
            try:
                ctx_data = json.loads(session.context_json or "{}")
                scan_meta = ctx_data.get("_scan_meta", {})
            except Exception:
                scan_meta = {}

            final_analysis = scan_meta.get("final_analysis", {})
            return {
                "session": session,
                "findings": findings_data,
                "commands": commands_data,
                "severity_counts": severity_counts,
                "grouped_findings": grouped,
                "cves": cves,
                "executive_summary": _executive_summary(session, severity_counts, len(commands)),
                "risk_rating": _risk_rating(severity_counts),
                "remediations": [_remediation_for(f) for f in findings_data],
                "severity_order": SEVERITY_ORDER,
                # Scan-engine metadata (populated by autonomous_deep_scan)
                "vulnerability_chains": scan_meta.get("vulnerability_chains", []),
                "attack_surface": scan_meta.get("attack_surface", {}),
                "tool_summaries": scan_meta.get("tool_summaries", []),
                "phases_completed": scan_meta.get("phases_completed", []),
                "stop_reason": scan_meta.get("stop_reason", ""),
                "total_scans": scan_meta.get("total_scans", 0),
                "duration_seconds": scan_meta.get("duration_seconds", 0),
                # AI final analysis narrative (populated after all tools exhausted)
                "final_analysis": final_analysis,
            }

    def _write_pdf(self, html_path: Path, slug: str) -> Path | None:
        try:
            from weasyprint import HTML
        except Exception:
            return None

        pdf_path = self.output_dir / f"{slug}.pdf"
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return pdf_path


def _finding_to_dict(finding: FindingRecord) -> dict[str, Any]:
    return {
        "id": finding.id,
        "tool": finding.tool,
        "type": finding.type,
        "detail": finding.detail,
        "severity": finding.severity.upper(),
        "created_at": finding.created_at,
    }


def _command_to_dict(command: CommandRecord) -> dict[str, Any]:
    return {
        "id": command.id,
        "tool": command.tool,
        "command": command.command,
        "exit_code": command.exit_code,
        "duration": command.duration,
        "timed_out": command.timed_out,
        "blocked": command.blocked,
        "dangerous": command.dangerous,
        "reason": command.reason,
        "created_at": command.created_at,
    }


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts.setdefault(finding["severity"], 0)
        counts[finding["severity"]] += 1
    return counts


def _group_findings(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped = {sev: [] for sev in SEVERITY_ORDER}
    for finding in findings:
        grouped.setdefault(finding["severity"], []).append(finding)
    return grouped


def _extract_cves(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    cves: dict[str, dict[str, str]] = {}
    for finding in findings:
        for cve_id in re.findall(r"CVE-\d{4}-\d+", finding["detail"], re.IGNORECASE):
            cves[cve_id.upper()] = {
                "id": cve_id.upper(),
                "severity": finding["severity"],
                "source": finding["tool"],
                "detail": finding["detail"],
            }
    return list(cves.values())


def _risk_rating(counts: dict[str, int]) -> str:
    if counts.get("CRITICAL", 0):
        return "Critical"
    if counts.get("HIGH", 0):
        return "High"
    if counts.get("MEDIUM", 0):
        return "Medium"
    if counts.get("LOW", 0):
        return "Low"
    return "Informational"


def _executive_summary(session: PentestSession, counts: dict[str, int], command_count: int) -> str:
    total = sum(counts.values())
    if total == 0:
        return (
            f"The assessment of {session.target} completed with {command_count} recorded "
            "commands and no findings captured in the session database."
        )

    notable = []
    for sev in SEVERITY_ORDER:
        count = counts.get(sev, 0)
        if count:
            notable.append(f"{count} {sev.lower()}")
    return (
        f"The assessment of {session.target} recorded {total} finding(s) across "
        f"{command_count} command(s). The current overall risk rating is "
        f"{_risk_rating(counts).lower()}, with {', '.join(notable)} item(s) requiring review."
    )


def _remediation_for(finding: dict[str, Any]) -> dict[str, str]:
    finding_type = finding["type"].lower()
    detail = finding["detail"]
    if "cve" in finding_type or "CVE-" in detail.upper():
        recommendation = (
            "Validate exploitability, apply the vendor patch or supported upgrade, "
            "and confirm the vulnerable version is no longer exposed."
        )
    elif "credential" in finding_type:
        recommendation = (
            "Rotate exposed credentials, review authentication logs, and enforce "
            "least privilege plus multi-factor authentication where supported."
        )
    elif "open_port" in finding_type or "service" in finding_type:
        recommendation = (
            "Confirm the service is business-required, restrict access with firewall "
            "rules, and disable or harden unnecessary exposed services."
        )
    elif "url" in finding_type:
        recommendation = (
            "Review the endpoint for sensitive data exposure, authentication gaps, "
            "and input validation issues before production exposure."
        )
    else:
        recommendation = (
            "Validate the finding, assign an owner, remediate according to severity, "
            "and retest to confirm closure."
        )

    return {
        "severity": finding["severity"],
        "finding": detail,
        "recommendation": recommendation,
    }


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    return slug or "proflupinmind-report"
