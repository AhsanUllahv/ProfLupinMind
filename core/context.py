from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict


@dataclass
class Finding:
    tool: str
    type: str
    detail: str
    severity: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


@dataclass
class SessionContext:
    target: str = ""
    scope: List[str] = field(default_factory=list)
    open_ports: Dict[str, List[str]] = field(default_factory=dict)
    services: Dict[str, str] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    commands_run: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    credentials: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)

    def add_finding(self, tool: str, type: str, detail: str, severity: str):
        # Deduplicate by detail string
        existing = [f.detail for f in self.findings]
        if detail not in existing:
            self.findings.append(Finding(tool=tool, type=type, detail=detail, severity=severity))

    def add_command(self, command: str):
        self.commands_run.append(command)

    def add_port(self, host: str, port: str):
        if host not in self.open_ports:
            self.open_ports[host] = []
        if port not in self.open_ports[host]:
            self.open_ports[host].append(port)

    def add_service(self, port_key: str, service: str):
        self.services[port_key] = service

    def add_url(self, url: str):
        if url not in self.urls:
            self.urls.append(url)

    def add_cve(self, cve: str):
        if cve not in self.cves:
            self.cves.append(cve)

    def get_findings_by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def to_string(self) -> str:
        if not self.target:
            return "No target set yet."

        lines = [f"Target: {self.target}"]

        if self.scope:
            lines.append(f"Scope: {', '.join(self.scope)}")

        if self.open_ports:
            lines.append("\nOpen Ports:")
            for host, ports in self.open_ports.items():
                lines.append(f"  {host}: {', '.join(ports)}")

        if self.services:
            lines.append("\nServices:")
            for port_key, svc in list(self.services.items())[:10]:
                lines.append(f"  {port_key}: {svc}")

        if self.urls:
            lines.append(f"\nDiscovered URLs ({len(self.urls)}):")
            for url in self.urls[:5]:
                lines.append(f"  {url}")

        if self.cves:
            lines.append(f"\nCVEs Found: {', '.join(self.cves)}")

        if self.credentials:
            lines.append(f"\nCredentials Found: {len(self.credentials)}")

        if self.findings:
            critical = len(self.get_findings_by_severity("CRITICAL"))
            high = len(self.get_findings_by_severity("HIGH"))
            lines.append(f"\nFindings: {len(self.findings)} total | {critical} Critical | {high} High")
            _sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            top = sorted(self.findings, key=lambda f: _sev_rank.get(f.severity, 4))[:8]
            for f in top:
                lines.append(f"  [{f.severity}] {f.type}: {f.detail}")

        if self.commands_run:
            lines.append(f"\nCommands run: {len(self.commands_run)}")
            lines.append(f"Last: {self.commands_run[-1]}")

        return "\n".join(lines)
