"""
Output Parser — automatically extract structured findings from raw tool output.

Each parser returns a ParseResult containing findings, ports, services, URLs,
CVEs, and credentials that are immediately usable by SessionContext.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from core.context import Finding


# ─── Result container ────────────────────────────────────────────────────────

@dataclass
class ParseResult:
    findings:    list[Finding]       = field(default_factory=list)
    ports:       dict[str, list[str]] = field(default_factory=dict)  # host → ["22/tcp", ...]
    services:    dict[str, str]       = field(default_factory=dict)  # "22/tcp" → "ssh OpenSSH 8.9"
    urls:        list[str]            = field(default_factory=list)
    subdomains:  list[str]            = field(default_factory=list)
    cves:        list[str]            = field(default_factory=list)
    credentials: list[str]            = field(default_factory=list)
    technologies: list[str]           = field(default_factory=list)

    def merge_into_context(self, context) -> None:
        """Push all extracted data into a SessionContext in-place."""
        for f in self.findings:
            context.add_finding(f.tool, f.type, f.detail, f.severity)
        for host, port_list in self.ports.items():
            for port in port_list:
                context.add_port(host, port)
        for key, svc in self.services.items():
            context.add_service(key, svc)
        for url in self.urls:
            context.add_url(url)
        for cve in self.cves:
            context.add_cve(cve)
        # credentials and subdomains go in as INFO findings so they appear in reports
        for cred in self.credentials:
            context.add_finding("credential_parser", "CREDENTIAL", cred, "HIGH")
        for sub in self.subdomains:
            context.add_finding("subdomain_parser", "SUBDOMAIN", sub, "INFO")

    def summary(self) -> dict[str, Any]:
        return {
            "findings":     len(self.findings),
            "ports":        sum(len(v) for v in self.ports.values()),
            "urls":         len(self.urls),
            "subdomains":   len(self.subdomains),
            "cves":         len(self.cves),
            "credentials":  len(self.credentials),
            "technologies": len(self.technologies),
        }


# ─── Dispatcher ──────────────────────────────────────────────────────────────

def parse(tool: str, output: str, target: str = "") -> ParseResult:
    """Route raw tool output to the correct parser and return a ParseResult."""
    tool = tool.lower().strip()
    if not output or not output.strip():
        return ParseResult()

    dispatcher: dict[str, Any] = {
        "nmap":            _parse_nmap,
        "rustscan":        _parse_nmap,       # feeds into nmap — same format
        "masscan":         _parse_masscan,
        "nuclei":          _parse_nuclei,
        "gobuster":        _parse_dir_enum,
        "ffuf":            _parse_dir_enum,
        "feroxbuster":     _parse_dir_enum,
        "dirb":            _parse_dirb,
        "dirsearch":       _parse_dir_enum,
        "wfuzz":           _parse_wfuzz,
        "nikto":           _parse_nikto,
        "sqlmap":          _parse_sqlmap,
        "hydra":           _parse_hydra,
        "hashcat":         _parse_hashcat,
        "john":            _parse_john,
        "subfinder":       _parse_subdomain_list,
        "amass":           _parse_subdomain_list,
        "dnsenum":         _parse_dnsenum,
        "fierce":          _parse_subdomain_list,
        "whatweb":         _parse_whatweb,
        "wpscan":          _parse_wpscan,
        "smbmap":          _parse_smbmap,
        "enum4linux":      _parse_enum4linux,
        "enum4linux-ng":   _parse_enum4linux,
        "netexec":         _parse_netexec,
        "responder":       _parse_responder,
        "httpx":           _parse_httpx,
        "katana":          _parse_url_list,
        "hakrawler":       _parse_url_list,
        "gau":             _parse_url_list,
        "waybackurls":     _parse_url_list,
        "trivy":           _parse_trivy,
        "checkov":         _parse_checkov,
        "searchsploit":    _parse_searchsploit,
        "dalfox":          _parse_dalfox,
        "xsser":           _parse_xsser,
        "wafw00f":         _parse_wafw00f,
    }

    parser = dispatcher.get(tool)
    if parser is None:
        return _parse_generic(tool, output)
    try:
        return parser(tool, output, target)
    except Exception:
        return _parse_generic(tool, output)


# ─── Helpers ─────────────────────────────────────────────────────────────────

_CVE_RE  = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
_URL_RE  = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
_IP_RE   = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _extract_cves(text: str) -> list[str]:
    return list(dict.fromkeys(c.upper() for c in _CVE_RE.findall(text)))


def _extract_urls(text: str) -> list[str]:
    return list(dict.fromkeys(_URL_RE.findall(text)))


def _severity_from_word(word: str) -> str:
    w = word.upper()
    if w in ("CRITICAL",): return "CRITICAL"
    if w in ("HIGH",):      return "HIGH"
    if w in ("MEDIUM",):    return "MEDIUM"
    if w in ("LOW",):       return "LOW"
    return "INFO"


# ─── nmap ────────────────────────────────────────────────────────────────────

def _parse_nmap(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()

    # Determine host from output or fall back to target
    current_host = target

    for line in output.splitlines():
        # Host header
        host_match = re.search(r'Nmap scan report for (?:[\w.-]+ \()?(\d[\d.]+)', line)
        if host_match:
            current_host = host_match.group(1)
            continue

        # Open port lines: "22/tcp   open  ssh     OpenSSH 8.9p1"
        port_match = re.match(
            r'\s*(\d+)/(tcp|udp)\s+(open(?:\|filtered)?)\s+(\S+)\s*(.*)', line
        )
        if port_match:
            port, proto, state, service, version = port_match.groups()
            port_key = f"{port}/{proto}"
            host_key  = current_host or target

            if host_key not in result.ports:
                result.ports[host_key] = []
            result.ports[host_key].append(port_key)

            svc_detail = f"{service} {version}".strip()
            result.services[port_key] = svc_detail

            finding_detail = f"{host_key}:{port}/{proto} — {svc_detail}"
            sev = "HIGH" if port in ("22", "23", "3389", "5900", "445", "139") else "INFO"
            result.findings.append(Finding(
                tool=tool, type="OPEN_PORT", detail=finding_detail, severity=sev
            ))
            continue

        # OS detection
        os_match = re.search(r'OS details?:\s*(.+)', line)
        if os_match:
            result.findings.append(Finding(
                tool=tool, type="OS_DETECTION",
                detail=f"{current_host}: {os_match.group(1).strip()}",
                severity="INFO"
            ))
            continue

        # NSE script output — vulnerability
        if re.search(r'\|\s*CVE-', line, re.IGNORECASE):
            cves = _extract_cves(line)
            for cve in cves:
                result.cves.append(cve)
                result.findings.append(Finding(
                    tool=tool, type="CVE", detail=f"{current_host}: {cve}", severity="HIGH"
                ))

        # Generic CVE mentions in output
        for cve in _extract_cves(line):
            if cve not in result.cves:
                result.cves.append(cve)

        # HTTP title from NSE
        title_match = re.search(r'\|_?http-title:\s*(.+)', line)
        if title_match:
            title = title_match.group(1).strip()
            if title and title.lower() not in ("did not follow redirect", ""):
                result.findings.append(Finding(
                    tool=tool, type="HTTP_TITLE",
                    detail=f"{current_host}: {title}", severity="INFO"
                ))

    return result


# ─── masscan ─────────────────────────────────────────────────────────────────

def _parse_masscan(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        # "Discovered open port 80/tcp on 192.168.1.1"
        m = re.search(r'Discovered open port (\d+)/(tcp|udp) on ([\d.]+)', line)
        if m:
            port, proto, host = m.groups()
            port_key = f"{port}/{proto}"
            if host not in result.ports:
                result.ports[host] = []
            result.ports[host].append(port_key)
            result.findings.append(Finding(
                tool=tool, type="OPEN_PORT",
                detail=f"{host}:{port}/{proto}",
                severity="INFO"
            ))
    return result


# ─── nuclei ──────────────────────────────────────────────────────────────────

def _parse_nuclei(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # Try JSON format first (nuclei -json)
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                template_id  = obj.get("template-id", obj.get("templateID", "unknown"))
                severity_raw = obj.get("info", {}).get("severity", obj.get("severity", "info"))
                matched_at   = obj.get("matched-at", obj.get("host", target))
                name         = obj.get("info", {}).get("name", template_id)
                severity     = _severity_from_word(severity_raw)

                # CVE extraction
                cve_tags = obj.get("info", {}).get("tags", "")
                if isinstance(cve_tags, str):
                    for cve in _extract_cves(cve_tags):
                        result.cves.append(cve)
                for cve in _extract_cves(template_id):
                    result.cves.append(cve)

                result.findings.append(Finding(
                    tool=tool, type=f"NUCLEI:{template_id.upper()}",
                    detail=f"{matched_at} — {name}",
                    severity=severity
                ))
                continue
            except json.JSONDecodeError:
                pass

        # Text format: [template-id] [type] [severity] url [extra]
        # e.g. "[CVE-2021-44228] [http] [critical] http://target/path"
        text_match = re.match(
            r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(\S+)(.*)', line
        )
        if text_match:
            tmpl, kind, sev_raw, url, extra = text_match.groups()
            severity = _severity_from_word(sev_raw)
            for cve in _extract_cves(tmpl):
                result.cves.append(cve)
            result.findings.append(Finding(
                tool=tool, type=f"NUCLEI:{tmpl.upper()}",
                detail=f"{url}{extra.strip()}",
                severity=severity
            ))
            if url.startswith("http"):
                result.urls.append(url)

    return result


# ─── directory enumeration (gobuster / ffuf / feroxbuster / dirsearch) ───────

def _parse_dir_enum(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()

    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("[INFO]"):
            continue

        # ffuf JSON per-result line
        if line.startswith("{") and '"status"' in line:
            try:
                obj = json.loads(line)
                url = obj.get("url", "")
                status = obj.get("status", 0)
                if url and status in (200, 201, 204, 301, 302, 307, 401, 403):
                    result.urls.append(url)
                    sev = "MEDIUM" if status in (200, 201) else "INFO"
                    result.findings.append(Finding(
                        tool=tool, type="DIR_FOUND",
                        detail=f"[{status}] {url}",
                        severity=sev
                    ))
                continue
            except json.JSONDecodeError:
                pass

        # gobuster: "/admin                 (Status: 200) [Size: 1234]"
        gob = re.match(r'(/\S*)\s+\(Status:\s*(\d+)\)', line)
        if gob:
            path, status = gob.groups()
            status_int = int(status)
            url = path if path.startswith("http") else f"{target.rstrip('/')}{path}"
            if status_int in (200, 201, 204, 301, 302, 307, 401, 403):
                result.urls.append(url)
                sev = "MEDIUM" if status_int in (200, 201) else "INFO"
                result.findings.append(Finding(
                    tool=tool, type="DIR_FOUND",
                    detail=f"[{status}] {url}",
                    severity=sev
                ))
            continue

        # feroxbuster: "200      GET  /admin"
        ferox = re.match(r'(\d{3})\s+\w+\s+(\d+[lw]\s+)?(/\S*)', line)
        if ferox:
            status, _, path = ferox.groups()
            url = path if path.startswith("http") else f"{target.rstrip('/')}{path}"
            if int(status) in (200, 201, 204, 301, 302, 307, 401, 403):
                result.urls.append(url)
                result.findings.append(Finding(
                    tool=tool, type="DIR_FOUND",
                    detail=f"[{status}] {url}",
                    severity="MEDIUM" if int(status) in (200, 201) else "INFO"
                ))
            continue

        # feroxbuster/newer tools: "200 GET 10l 20w 123c https://target/admin"
        status_url = re.search(r'\b(\d{3})\s+\w+\s+.*?(https?://\S+)', line)
        if status_url:
            status, url = status_url.groups()
            if int(status) in (200, 201, 204, 301, 302, 307, 401, 403):
                result.urls.append(url)
                result.findings.append(Finding(
                    tool=tool, type="DIR_FOUND",
                    detail=f"[{status}] {url}",
                    severity="MEDIUM" if int(status) in (200, 201) else "INFO"
                ))
            continue

        # ffuf text: "admin [Status: 200, Size: 1234, Words: 10, Lines: 3]"
        ffuf_text = re.match(r'(\S+)\s+\[Status:\s*(\d+),', line)
        if ffuf_text:
            path, status = ffuf_text.groups()
            url = path if path.startswith("http") else f"{target.rstrip('/')}/{path.lstrip('/')}"
            if int(status) in (200, 201, 204, 301, 302, 307, 401, 403):
                result.urls.append(url)
                result.findings.append(Finding(
                    tool=tool, type="DIR_FOUND",
                    detail=f"[{status}] {url}",
                    severity="MEDIUM" if int(status) in (200, 201) else "INFO"
                ))
            continue

        # dirsearch: "[200] - 1KB - /admin"
        dirsearch_text = re.match(r'\[(\d{3})\]\s+-\s+.*?\s+-\s+(\S+)', line)
        if dirsearch_text:
            status, path = dirsearch_text.groups()
            url = path if path.startswith("http") else f"{target.rstrip('/')}/{path.lstrip('/')}"
            if int(status) in (200, 201, 204, 301, 302, 307, 401, 403):
                result.urls.append(url)
                result.findings.append(Finding(
                    tool=tool, type="DIR_FOUND",
                    detail=f"[{status}] {url}",
                    severity="MEDIUM" if int(status) in (200, 201) else "INFO"
                ))
            continue

        # Generic URL extraction as fallback
        for url in _extract_urls(line):
            if url not in result.urls:
                result.urls.append(url)

    return result


def _parse_dirb(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        # "+ http://target/admin (CODE:200|SIZE:1234)"
        m = re.match(r'\+\s+(https?://\S+)\s+\(CODE:(\d+)\|', line)
        if m:
            url, code = m.groups()
            result.urls.append(url)
            result.findings.append(Finding(
                tool=tool, type="DIR_FOUND",
                detail=f"[{code}] {url}",
                severity="MEDIUM" if code == "200" else "INFO"
            ))
        # Directory marker
        if line.strip().startswith("==> DIRECTORY:"):
            url = line.split(":", 1)[1].strip()
            result.urls.append(url)
    return result


def _parse_wfuzz(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        # "000000001:   200   C=200    1 L     3 W     11 Ch    "path""
        m = re.search(r'(\d{3})\s+C=(\d+).*?"([^"]+)"', line)
        if m:
            _, code, path = m.groups()
            url = path if path.startswith("http") else f"{target.rstrip('/')}/{path.lstrip('/')}"
            result.urls.append(url)
            result.findings.append(Finding(
                tool=tool, type="FUZZ_FOUND",
                detail=f"[{code}] {url}",
                severity="MEDIUM" if code == "200" else "INFO"
            ))
    return result


# ─── nikto ───────────────────────────────────────────────────────────────────

def _parse_nikto(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        line = line.strip()
        # "+ /path: description" or "+ OSVDB-XXXX: ..."
        if not line.startswith("+"):
            continue
        content = line[1:].strip()
        if not content:
            continue

        sev = "INFO"
        if any(w in content.lower() for w in ("vulnerab", "injection", "xss", "rce", "overflow", "exploit")):
            sev = "HIGH"
        elif any(w in content.lower() for w in ("outdated", "disclosure", "found", "misconfigur")):
            sev = "MEDIUM"

        for cve in _extract_cves(content):
            result.cves.append(cve)

        result.findings.append(Finding(
            tool=tool, type="NIKTO_FINDING",
            detail=content[:300],
            severity=sev
        ))
    return result


# ─── sqlmap ──────────────────────────────────────────────────────────────────

def _parse_sqlmap(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    injection_types = {
        "boolean-based blind": "SQLI_BOOLEAN",
        "time-based blind":    "SQLI_TIME",
        "union query":         "SQLI_UNION",
        "error-based":         "SQLI_ERROR",
        "stacked queries":     "SQLI_STACKED",
    }

    for line in output.splitlines():
        lower = line.lower()

        # Injection found
        for pattern, finding_type in injection_types.items():
            if pattern in lower and ("injectable" in lower or "is '" in lower or "injection" in lower):
                result.findings.append(Finding(
                    tool=tool, type=finding_type,
                    detail=line.strip()[:300],
                    severity="CRITICAL"
                ))

        # Parameter is vulnerable
        param_match = re.search(r"parameter ['\"](\w+)['\"] (?:is|appears to be) ['\"]?([^'\"]+)['\"]? injectable", line, re.IGNORECASE)
        if param_match:
            param, inj_type = param_match.groups()
            result.findings.append(Finding(
                tool=tool, type="SQLI_PARAMETER",
                detail=f"Param '{param}' injectable via {inj_type}",
                severity="CRITICAL"
            ))

        # Database extracted
        db_match = re.search(r'\[\*\]\s+(\w+)\s*$', line)
        if db_match and "available database" in output.lower():
            result.findings.append(Finding(
                tool=tool, type="DATABASE_FOUND",
                detail=f"Database: {db_match.group(1)}",
                severity="HIGH"
            ))

        # Credentials
        cred_match = re.search(r'(\w+)\s+\|\s+(\S+)\s+\|\s+(\S+)', line)
        if cred_match and any(w in output.lower() for w in ("username", "password", "hash")):
            result.credentials.append(cred_match.group(0).strip())

    return result


# ─── hydra ───────────────────────────────────────────────────────────────────

def _parse_hydra(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        # "[PORT][service] host: X   login: Y   password: Z"
        m = re.search(
            r'\[(\d+)\]\[(\w[\w-]*)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)',
            line
        )
        if m:
            port, svc, host, login, password = m.groups()
            cred = f"{login}:{password} @ {host}:{port}/{svc}"
            result.credentials.append(cred)
            result.findings.append(Finding(
                tool=tool, type="CREDENTIAL_FOUND",
                detail=cred,
                severity="CRITICAL"
            ))
    return result


# ─── hashcat ─────────────────────────────────────────────────────────────────

def _parse_hashcat(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        line = line.strip()
        # "hash:password" or "user:hash:password"
        if ":" in line and not line.startswith("#") and not line.startswith("["):
            parts = line.split(":")
            if len(parts) >= 2 and len(parts[-1]) >= 1 and len(parts[-1]) <= 64:
                cred = line
                result.credentials.append(cred)
                result.findings.append(Finding(
                    tool=tool, type="HASH_CRACKED",
                    detail=cred[:200],
                    severity="HIGH"
                ))
    return result


# ─── john ────────────────────────────────────────────────────────────────────

def _parse_john(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        # john --show output: "username:password:..."
        m = re.match(r'^(\S+):(\S+):', line)
        if m:
            user, password = m.group(1), m.group(2)
            cred = f"{user}:{password}"
            result.credentials.append(cred)
            result.findings.append(Finding(
                tool=tool, type="HASH_CRACKED",
                detail=cred,
                severity="HIGH"
            ))
        # Session cracked summary
        cracked_match = re.search(r'(\d+) password hashes cracked', line, re.IGNORECASE)
        if cracked_match and int(cracked_match.group(1)) > 0:
            result.findings.append(Finding(
                tool=tool, type="HASHES_CRACKED",
                detail=f"{cracked_match.group(1)} passwords cracked",
                severity="HIGH"
            ))
    return result


# ─── subdomain list parsers ──────────────────────────────────────────────────

def _parse_subdomain_list(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    domain_re = re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    )
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("[") or line.startswith("#"):
            continue
        # Skip lines that are obviously not hostnames
        if " " in line and not re.match(r'^\S+\.\S+', line):
            continue
        match = domain_re.search(line)
        if match:
            sub = match.group(0).lower()
            if sub not in result.subdomains:
                result.subdomains.append(sub)
                result.findings.append(Finding(
                    tool=tool, type="SUBDOMAIN",
                    detail=sub,
                    severity="INFO"
                ))
    return result


def _parse_dnsenum(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        line = line.strip()
        # IP → hostname mappings
        ip_host = re.match(r'(\S+\.\S+)\s+\d+\s+IN\s+A\s+([\d.]+)', line)
        if ip_host:
            hostname, ip = ip_host.groups()
            result.subdomains.append(hostname)
            result.findings.append(Finding(
                tool=tool, type="DNS_RECORD",
                detail=f"{hostname} → {ip}",
                severity="INFO"
            ))
        # Zone transfer success
        if "zone transfer" in line.lower() and ("success" in line.lower() or "axfr" in line.lower()):
            result.findings.append(Finding(
                tool=tool, type="ZONE_TRANSFER",
                detail=f"Zone transfer succeeded: {line.strip()}",
                severity="HIGH"
            ))
    return result


# ─── whatweb ─────────────────────────────────────────────────────────────────

def _parse_whatweb(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    tech_re = re.compile(r'([A-Za-z][A-Za-z0-9._-]+(?:\[[\d.]+\])?)')
    for line in output.splitlines():
        if not line.strip():
            continue
        # "http://target [200] WordPress[5.8], Apache[2.4.51], ..."
        url_match = re.match(r'(https?://\S+)\s+\[(\d+)\]\s+(.*)', line)
        if url_match:
            url, code, tech_str = url_match.groups()
            result.urls.append(url)
            techs = [t.strip() for t in tech_str.split(",") if t.strip()]
            for tech in techs:
                clean = tech_re.match(tech)
                if clean:
                    result.technologies.append(clean.group(1))
                    result.findings.append(Finding(
                        tool=tool, type="TECHNOLOGY",
                        detail=tech.strip()[:100],
                        severity="INFO"
                    ))
    return result


# ─── wpscan ──────────────────────────────────────────────────────────────────

def _parse_wpscan(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()

    # Try JSON output first (wpscan --format json)
    stripped = output.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)

            # WordPress version
            version_info = data.get("version") or {}
            wp_ver = version_info.get("number", "")
            if wp_ver:
                result.findings.append(Finding(
                    tool=tool, type="WP_VERSION",
                    detail=f"WordPress {wp_ver}",
                    severity="INFO"
                ))
            for vuln in version_info.get("vulnerabilities", []):
                title = vuln.get("title", "")
                refs = vuln.get("references", {})
                cves = refs.get("cve", []) if isinstance(refs, dict) else []
                for cve in cves:
                    cve_id = cve if cve.upper().startswith("CVE") else f"CVE-{cve}"
                    result.cves.append(cve_id)
                sev = "CRITICAL" if any(w in title.lower() for w in ("rce", "remote code", "unauthenticated")) else "HIGH"
                result.findings.append(Finding(
                    tool=tool, type="WP_VERSION_VULN",
                    detail=f"{title} (fixed: {vuln.get('fixed_in', 'N/A')})",
                    severity=sev
                ))

            # Plugins
            for slug, plugin in (data.get("plugins") or {}).items():
                for vuln in plugin.get("vulnerabilities", []):
                    title = vuln.get("title", slug)
                    refs = vuln.get("references", {})
                    for cve in (refs.get("cve", []) if isinstance(refs, dict) else []):
                        result.cves.append(cve if cve.upper().startswith("CVE") else f"CVE-{cve}")
                    sev = "CRITICAL" if any(w in title.lower() for w in ("rce", "injection", "unauthenticated")) else "HIGH"
                    result.findings.append(Finding(
                        tool=tool, type="WP_PLUGIN_VULN",
                        detail=f"{slug}: {title}",
                        severity=sev
                    ))

            # Users
            for username in (data.get("users") or {}):
                result.findings.append(Finding(
                    tool=tool, type="WP_USER",
                    detail=f"User: {username}",
                    severity="MEDIUM"
                ))

            # Interesting findings
            for item in (data.get("interesting_findings") or []):
                entries = item.get("interesting_entries", [])
                for cve in _extract_cves(str(entries)):
                    result.cves.append(cve)
                if entries:
                    result.findings.append(Finding(
                        tool=tool, type="WP_INTERESTING",
                        detail=str(entries)[:300],
                        severity="INFO"
                    ))

            return result
        except (json.JSONDecodeError, AttributeError):
            pass

    # Text format fallback
    for line in output.splitlines():
        line = line.strip()
        ver_match = re.search(r'WordPress version ([\d.]+)', line, re.IGNORECASE)
        if ver_match:
            result.findings.append(Finding(
                tool=tool, type="WP_VERSION",
                detail=f"WordPress {ver_match.group(1)}",
                severity="INFO"
            ))
        if re.search(r'\[!\]|vulnerability|vulnerable|outdated', line, re.IGNORECASE):
            sev = "HIGH" if any(w in line.lower() for w in ("critical", "rce", "injection", "xss")) else "MEDIUM"
            result.findings.append(Finding(
                tool=tool, type="WP_VULNERABILITY",
                detail=line[:300],
                severity=sev
            ))
        for cve in _extract_cves(line):
            result.cves.append(cve)
        user_match = re.search(r'User(name)?:\s+(\S+)', line, re.IGNORECASE)
        if user_match:
            result.findings.append(Finding(
                tool=tool, type="WP_USER",
                detail=f"User: {user_match.group(2)}",
                severity="MEDIUM"
            ))
    return result


# ─── smbmap ──────────────────────────────────────────────────────────────────

def _parse_smbmap(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        # "    READ ONLY   /share_name   Mapped, no access comment"
        # "    READ, WRITE /writable"
        m = re.search(
            r'(READ(?:,\s*WRITE)?|WRITE|NO ACCESS)\s+(/?\S+)\s*(.*)',
            line, re.IGNORECASE
        )
        if m:
            access, share, comment = m.groups()
            access = access.strip().upper()
            sev = "HIGH" if "WRITE" in access else ("MEDIUM" if "READ" in access else "INFO")
            result.findings.append(Finding(
                tool=tool, type="SMB_SHARE",
                detail=f"{access}: {share.strip()} — {comment.strip()[:100]}",
                severity=sev
            ))
    return result


# ─── enum4linux ──────────────────────────────────────────────────────────────

def _parse_enum4linux(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        line = line.strip()

        # User account: "user:[username] rid:[0x...]"
        user_match = re.search(r'user:\[([^\]]+)\]\s+rid:\[([^\]]+)\]', line, re.IGNORECASE)
        if user_match:
            username, rid = user_match.groups()
            result.findings.append(Finding(
                tool=tool, type="AD_USER",
                detail=f"User: {username} (RID: {rid})",
                severity="MEDIUM"
            ))
            continue

        # Share: "//target/share   Mapping: OK, Listing: OK"
        share_match = re.search(r'(//.+?/\S+)\s+Mapping:\s*(\w+)', line, re.IGNORECASE)
        if share_match:
            share, status = share_match.groups()
            if status.upper() == "OK":
                result.findings.append(Finding(
                    tool=tool, type="SMB_SHARE",
                    detail=f"Accessible: {share}",
                    severity="MEDIUM"
                ))
            continue

        # Password policy
        if "minimum password length" in line.lower():
            result.findings.append(Finding(
                tool=tool, type="PASSWORD_POLICY",
                detail=line[:200],
                severity="LOW"
            ))

        # Null session
        if "null session" in line.lower() and "success" in line.lower():
            result.findings.append(Finding(
                tool=tool, type="NULL_SESSION",
                detail="Null session authentication succeeded",
                severity="HIGH"
            ))

    return result


# ─── netexec / crackmapexec ───────────────────────────────────────────────────

def _parse_netexec(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        line = line.strip()

        # Credentials working: "[+] target\user:pass (Pwn3d!)"
        if "[+]" in line:
            sev = "CRITICAL" if "pwn3d" in line.lower() else "HIGH"
            result.findings.append(Finding(
                tool=tool, type="VALID_CREDENTIAL",
                detail=line[:300],
                severity=sev
            ))

        # Hash / secret dumped
        if re.search(r'[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}', line):
            result.credentials.append(line.strip())
            result.findings.append(Finding(
                tool=tool, type="NTLM_HASH",
                detail=line.strip()[:300],
                severity="CRITICAL"
            ))
    return result


# ─── responder ───────────────────────────────────────────────────────────────

def _parse_responder(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        # "NTLMv2-SSP Hash : domain\user::DOMAIN:..."
        if re.search(r'NTLMv[12].*Hash\s*:', line, re.IGNORECASE):
            hash_match = re.search(r':\s*(\S+::.+)$', line)
            if hash_match:
                hash_val = hash_match.group(1).strip()
                result.credentials.append(hash_val)
                result.findings.append(Finding(
                    tool=tool, type="NTLM_HASH_CAPTURED",
                    detail=hash_val[:300],
                    severity="CRITICAL"
                ))
        # Cleartext
        if re.search(r'cleartext password', line, re.IGNORECASE):
            result.findings.append(Finding(
                tool=tool, type="CLEARTEXT_PASSWORD",
                detail=line.strip()[:200],
                severity="CRITICAL"
            ))
    return result


# ─── httpx ───────────────────────────────────────────────────────────────────

def _parse_httpx(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        # JSON per-line mode
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                url = obj.get("url", obj.get("input", ""))
                status = obj.get("status-code", 0)
                title = obj.get("title", "")
                techs = obj.get("tech", [])

                if url:
                    result.urls.append(url)
                    result.findings.append(Finding(
                        tool=tool, type="LIVE_HOST",
                        detail=f"[{status}] {url} — {title}",
                        severity="INFO"
                    ))
                for tech in (techs if isinstance(techs, list) else [techs]):
                    if tech:
                        result.technologies.append(str(tech))
                continue
            except json.JSONDecodeError:
                pass

        # Text: "https://target [200] [Title] [Tech, Tech]"
        url_match = re.match(r'(https?://\S+)', line)
        if url_match:
            result.urls.append(url_match.group(1))
            result.findings.append(Finding(
                tool=tool, type="LIVE_HOST",
                detail=line[:200],
                severity="INFO"
            ))
    return result


# ─── URL list (katana, hakrawler, gau, waybackurls) ──────────────────────────

def _parse_url_list(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        url = line.strip()
        if url.startswith("http"):
            result.urls.append(url)
            # Flag potentially interesting endpoints
            if any(kw in url.lower() for kw in (
                "admin", "api", "login", "upload", "config", "backup",
                "debug", "test", "dev", ".env", ".git", "secret", "token"
            )):
                result.findings.append(Finding(
                    tool=tool, type="INTERESTING_URL",
                    detail=url,
                    severity="MEDIUM"
                ))
    return result


# ─── trivy ───────────────────────────────────────────────────────────────────

def _parse_trivy(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()

    # Try JSON mode
    try:
        data = json.loads(output)
        for report in data.get("Results", []):
            for vuln in report.get("Vulnerabilities", []):
                cve_id   = vuln.get("VulnerabilityID", "")
                sev_raw  = vuln.get("Severity", "INFO")
                pkg      = vuln.get("PkgName", "")
                ver      = vuln.get("InstalledVersion", "")
                fixed    = vuln.get("FixedVersion", "")
                title    = vuln.get("Title", "")
                severity = _severity_from_word(sev_raw)

                if cve_id:
                    result.cves.append(cve_id)
                result.findings.append(Finding(
                    tool=tool, type=f"CONTAINER_CVE:{sev_raw.upper()}",
                    detail=f"{cve_id} in {pkg}@{ver} (fixed: {fixed or 'N/A'}) — {title}",
                    severity=severity
                ))
        return result
    except (json.JSONDecodeError, AttributeError):
        pass

    # Text fallback
    for line in output.splitlines():
        for cve in _extract_cves(line):
            result.cves.append(cve)
            m = re.search(r'(CRITICAL|HIGH|MEDIUM|LOW)', line, re.IGNORECASE)
            sev = _severity_from_word(m.group(1)) if m else "INFO"
            result.findings.append(Finding(
                tool=tool, type="CONTAINER_VULN",
                detail=line.strip()[:300],
                severity=sev
            ))
    return result


# ─── checkov ─────────────────────────────────────────────────────────────────

def _parse_checkov(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()

    # Try JSON output first (checkov -o json)
    stripped = output.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            data = json.loads(stripped)
            # checkov may output a list when multiple frameworks run
            if isinstance(data, list):
                items = data
            else:
                items = [data]

            for item in items:
                results_block = item.get("results", item)
                failed = results_block.get("failed_checks", [])
                summary = item.get("summary", {})

                for check in failed:
                    check_id   = check.get("check_id", "UNKNOWN")
                    check_name = check.get("check_name", "")
                    resource   = check.get("resource", "")
                    file_path  = check.get("file_path", "")
                    sev = "HIGH" if any(w in check_name.lower() for w in (
                        "public", "encrypt", "iam", "secret", "admin", "root", "password"
                    )) else "MEDIUM"
                    result.findings.append(Finding(
                        tool=tool, type="IAC_MISCONFIGURATION",
                        detail=f"{check_id}: {check_name} | {resource} ({file_path})",
                        severity=sev
                    ))

                passed = summary.get("passed", 0)
                failed_count = summary.get("failed", 0)
                if passed or failed_count:
                    result.findings.append(Finding(
                        tool=tool, type="IAC_SUMMARY",
                        detail=f"passed={passed} failed={failed_count}",
                        severity="INFO"
                    ))
            return result
        except (json.JSONDecodeError, AttributeError):
            pass

    # Text fallback
    for line in output.splitlines():
        m = re.search(r'FAILED.*?Check:\s*(CKV_\w+)', line, re.IGNORECASE)
        if m:
            check_id = m.group(1)
            result.findings.append(Finding(
                tool=tool, type="IAC_MISCONFIGURATION",
                detail=f"{check_id}: {line.strip()[:200]}",
                severity="MEDIUM"
            ))
    return result


# ─── searchsploit ────────────────────────────────────────────────────────────

def _parse_searchsploit(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("-") or line.startswith("="):
            continue
        # "Apache 2.4.49 - Path Traversal & Remote Code Execution  | exploits/..."
        if "|" in line:
            parts = line.split("|")
            name = parts[0].strip()
            path = parts[1].strip() if len(parts) > 1 else ""
            sev = "HIGH"
            if any(w in name.lower() for w in ("remote code", "rce", "privilege", "root")):
                sev = "CRITICAL"
            for cve in _extract_cves(name):
                result.cves.append(cve)
            result.findings.append(Finding(
                tool=tool, type="EXPLOIT_AVAILABLE",
                detail=f"{name} ({path})",
                severity=sev
            ))
    return result


# ─── dalfox ──────────────────────────────────────────────────────────────────

def _parse_dalfox(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # "[POC][G][REFLECTED][http://...] ..."
        if "[POC]" in line or "[WEAK]" in line or "FOUND" in line.upper():
            url_match = re.search(r'https?://\S+', line)
            url = url_match.group(0) if url_match else target
            sev = "HIGH" if "[POC]" in line else "MEDIUM"
            result.findings.append(Finding(
                tool=tool, type="XSS_FOUND",
                detail=line[:300],
                severity=sev
            ))
            result.urls.append(url)
    return result


# ─── xsser ───────────────────────────────────────────────────────────────────

def _parse_xsser(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        if re.search(r'xss|injection|vector', line, re.IGNORECASE):
            sev = "HIGH" if "success" in line.lower() or "exploit" in line.lower() else "MEDIUM"
            result.findings.append(Finding(
                tool=tool, type="XSS_FOUND",
                detail=line.strip()[:300],
                severity=sev
            ))
    return result


# ─── wafw00f ─────────────────────────────────────────────────────────────────

def _parse_wafw00f(tool: str, output: str, target: str) -> ParseResult:
    result = ParseResult()
    for line in output.splitlines():
        # "The site http://target is behind Cloudflare"
        waf_match = re.search(r'is behind (.+?)(?:\s+WAF|$)', line, re.IGNORECASE)
        if waf_match:
            waf_name = waf_match.group(1).strip()
            result.findings.append(Finding(
                tool=tool, type="WAF_DETECTED",
                detail=f"WAF detected: {waf_name}",
                severity="INFO"
            ))
        # "No WAF detected"
        if re.search(r'no waf', line, re.IGNORECASE):
            result.findings.append(Finding(
                tool=tool, type="WAF_ABSENT",
                detail="No WAF detected — target may be easier to attack",
                severity="MEDIUM"
            ))
    return result


# ─── Generic fallback ────────────────────────────────────────────────────────

def _parse_generic(tool: str, output: str) -> ParseResult:
    result = ParseResult()

    # Always extract CVEs from any tool output
    for cve in _extract_cves(output):
        result.cves.append(cve)
        result.findings.append(Finding(
            tool=tool, type="CVE",
            detail=cve,
            severity="HIGH"
        ))

    # Extract any URLs
    for url in _extract_urls(output):
        result.urls.append(url)

    # High-signal keyword findings
    patterns = [
        (r'(?i)root\s+shell|got\s+root|#\s*id\s*=\s*0',          "ROOT_SHELL",    "CRITICAL"),
        (r'(?i)password(?:s)?\s*[:=]\s*(\S+)',                     "PASSWORD",      "CRITICAL"),
        (r'(?i)private.{0,10}key',                                  "PRIVATE_KEY",   "CRITICAL"),
        (r'(?i)access[_\s]key|secret[_\s]key|api[_\s]key',         "API_KEY",       "CRITICAL"),
        (r'(?i)authentication\s+bypass',                            "AUTH_BYPASS",   "CRITICAL"),
        (r'(?i)remote\s+code\s+execution|rce',                     "RCE",           "CRITICAL"),
        (r'(?i)sql\s+injection',                                    "SQLI",          "CRITICAL"),
        (r'(?i)cross.site\s+scripting|xss\s+(?:found|confirmed)',  "XSS",           "HIGH"),
        (r'(?i)server.side\s+request\s+forgery|ssrf',              "SSRF",          "HIGH"),
        (r'(?i)path\s+traversal|directory\s+traversal',            "PATH_TRAVERSAL","HIGH"),
        (r'(?i)local\s+file\s+inclusion|lfi',                      "LFI",           "HIGH"),
        (r'(?i)default\s+(?:credential|password)',                  "DEFAULT_CREDS", "HIGH"),
        (r'(?i)privilege\s+escalation|privesc',                    "PRIVESC",       "HIGH"),
        (r'(?i)sensitive\s+(?:file|data)\s+(?:found|exposed)',     "DATA_EXPOSURE", "MEDIUM"),
    ]

    seen = set()
    for pattern, finding_type, sev in patterns:
        for match in re.finditer(pattern, output):
            line = output[max(0, match.start() - 40):match.end() + 80].strip()
            if finding_type not in seen:
                seen.add(finding_type)
                result.findings.append(Finding(
                    tool=tool, type=finding_type,
                    detail=line[:300],
                    severity=sev
                ))

    return result
