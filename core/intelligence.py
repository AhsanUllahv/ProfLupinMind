"""
Intelligent Decision Engine — target profiling, tool effectiveness mapping,
parameter optimization, and attack chain generation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ─── Target Types ────────────────────────────────────────────────────────────

class TargetType(str, Enum):
    WEB        = "web"
    NETWORK    = "network"
    API        = "api"
    CLOUD      = "cloud"
    MOBILE     = "mobile"
    BINARY     = "binary"
    CONTAINER  = "container"
    UNKNOWN    = "unknown"


class RiskLevel(str, Enum):
    MINIMAL  = "minimal"
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class TargetProfile:
    target:          str
    target_type:     TargetType             = TargetType.UNKNOWN
    resolved_ips:    list[str]              = field(default_factory=list)
    open_ports:      list[int]              = field(default_factory=list)
    services:        dict[int, str]         = field(default_factory=dict)
    technologies:    list[str]              = field(default_factory=list)
    cms:             str                    = ""
    cloud_provider:  str                    = ""
    security_headers: dict[str, str]        = field(default_factory=dict)
    ssl_info:        dict[str, str]         = field(default_factory=dict)
    subdomains:      list[str]              = field(default_factory=list)
    endpoints:       list[str]             = field(default_factory=list)
    attack_surface:  float                  = 0.0   # 0–10
    risk_level:      RiskLevel              = RiskLevel.MINIMAL
    confidence:      float                  = 0.0   # 0–1
    flags:           dict[str, bool]        = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target":         self.target,
            "target_type":    self.target_type.value,
            "open_ports":     self.open_ports,
            "services":       {str(k): v for k, v in self.services.items()},
            "technologies":   self.technologies,
            "cms":            self.cms,
            "cloud_provider": self.cloud_provider,
            "attack_surface": self.attack_surface,
            "risk_level":     self.risk_level.value,
            "confidence":     self.confidence,
            "subdomains":     self.subdomains[:10],
            "endpoints":      self.endpoints[:10],
            "flags":          self.flags,
        }


@dataclass
class AttackStep:
    step:        int
    tool:        str
    goal:        str
    reason:      str
    params:      dict[str, Any] = field(default_factory=dict)
    condition:   str = "always"
    duration_est: float = 30.0  # seconds
    success_prob: float = 0.8


@dataclass
class AttackChain:
    name:         str
    target_type:  TargetType
    steps:        list[AttackStep] = field(default_factory=list)
    risk_level:   RiskLevel = RiskLevel.LOW
    total_time:   float = 0.0
    success_prob: float = 0.0

    def calculate_metrics(self) -> None:
        self.total_time = sum(s.duration_est for s in self.steps)
        if self.steps:
            compound = 1.0
            for s in self.steps:
                compound *= s.success_prob
            self.success_prob = round(compound, 3)

    def to_dict(self) -> dict[str, Any]:
        self.calculate_metrics()
        return {
            "name":        self.name,
            "target_type": self.target_type.value,
            "risk_level":  self.risk_level.value,
            "total_time_seconds": self.total_time,
            "success_probability": self.success_prob,
            "steps": [
                {
                    "step":      s.step,
                    "tool":      s.tool,
                    "goal":      s.goal,
                    "reason":    s.reason,
                    "params":    s.params,
                    "condition": s.condition,
                    "duration_est": s.duration_est,
                }
                for s in self.steps
            ],
        }


# ─── Tool Effectiveness Map ───────────────────────────────────────────────────
# effectiveness: 0.0–1.0 per target type

TOOL_EFFECTIVENESS: dict[str, dict[TargetType, float]] = {
    "nmap":        {TargetType.NETWORK: 0.95, TargetType.WEB: 0.80, TargetType.API: 0.75, TargetType.CLOUD: 0.60},
    "masscan":     {TargetType.NETWORK: 0.90, TargetType.WEB: 0.70},
    "rustscan":    {TargetType.NETWORK: 0.88, TargetType.WEB: 0.72},
    "nikto":       {TargetType.WEB: 0.85, TargetType.API: 0.65},
    "gobuster":    {TargetType.WEB: 0.88, TargetType.API: 0.75},
    "ffuf":        {TargetType.WEB: 0.90, TargetType.API: 0.85},
    "nuclei":      {TargetType.WEB: 0.95, TargetType.API: 0.88, TargetType.CLOUD: 0.70},
    "sqlmap":      {TargetType.WEB: 0.92, TargetType.API: 0.80},
    "dalfox":      {TargetType.WEB: 0.88},
    "subfinder":   {TargetType.WEB: 0.92, TargetType.API: 0.85, TargetType.CLOUD: 0.80},
    "amass":       {TargetType.WEB: 0.90, TargetType.API: 0.82},
    "httpx":       {TargetType.WEB: 0.88, TargetType.API: 0.90},
    "katana":      {TargetType.WEB: 0.85, TargetType.API: 0.80},
    "feroxbuster": {TargetType.WEB: 0.87, TargetType.API: 0.80},
    "wpscan":      {TargetType.WEB: 0.95},
    "enum4linux":  {TargetType.NETWORK: 0.90},
    "smbmap":      {TargetType.NETWORK: 0.88},
    "hydra":       {TargetType.NETWORK: 0.82, TargetType.WEB: 0.75},
    "hashcat":     {TargetType.NETWORK: 0.85},
    "john":        {TargetType.NETWORK: 0.80},
    "metasploit":  {TargetType.NETWORK: 0.85, TargetType.WEB: 0.70, TargetType.BINARY: 0.75},
    "msfvenom":    {TargetType.BINARY: 0.90, TargetType.NETWORK: 0.80},
    "gdb":         {TargetType.BINARY: 0.92},
    "radare2":     {TargetType.BINARY: 0.90},
    "ghidra":      {TargetType.BINARY: 0.95},
    "pwntools":    {TargetType.BINARY: 0.88},
    "binwalk":     {TargetType.BINARY: 0.85},
    "prowler":     {TargetType.CLOUD: 0.92},
    "scout-suite": {TargetType.CLOUD: 0.90},
    "trivy":       {TargetType.CONTAINER: 0.92, TargetType.CLOUD: 0.75},
    "kube-hunter": {TargetType.CONTAINER: 0.88},
    "checkov":     {TargetType.CLOUD: 0.85, TargetType.CONTAINER: 0.80},
    "wafw00f":     {TargetType.WEB: 0.92},
    "theharvester":{TargetType.WEB: 0.80, TargetType.NETWORK: 0.75},
    "shodan":      {TargetType.NETWORK: 0.88, TargetType.CLOUD: 0.82},
    "whatweb":     {TargetType.WEB: 0.88},
    "arjun":       {TargetType.API: 0.90, TargetType.WEB: 0.80},
    "jwt-analyzer":{TargetType.API: 0.92},
    "graphql-scanner": {TargetType.API: 0.90},
}


# ─── Intelligence Engine ──────────────────────────────────────────────────────

class IntelligentDecisionEngine:
    """
    Profiles a target, scores its attack surface, selects optimal tools,
    optimizes their parameters, and generates attack chains.
    """

    # ── Target Detection ─────────────────────────────────────────────────────

    def detect_target_type(self, target: str, context_hints: dict[str, Any] | None = None) -> TargetType:
        hints = context_hints or {}
        ports  = hints.get("open_ports", [])
        services = hints.get("services", {})
        banner = " ".join(str(v) for v in services.values()).lower()

        # API indicators
        if any(kw in target.lower() for kw in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
            return TargetType.API
        if any(kw in banner for kw in ["graphql", "swagger", "openapi", "grpc"]):
            return TargetType.API

        # Cloud
        cloud_domains = ["amazonaws.com", "azurewebsites.net", "appspot.com",
                         "cloudfront.net", "s3.", "storage.googleapis"]
        if any(d in target.lower() for d in cloud_domains):
            return TargetType.CLOUD

        # Container/Kubernetes
        if any(kw in target.lower() for kw in ["k8s", "kubernetes", "docker"]):
            return TargetType.CONTAINER
        if 2375 in ports or 2376 in ports or 6443 in ports:
            return TargetType.CONTAINER

        # Binary / local file
        if re.match(r"^(\.{0,2}/|[A-Za-z]:\\)", target) or target.endswith((".exe", ".elf", ".bin")):
            return TargetType.BINARY

        # Web
        web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
        if target.startswith(("http://", "https://")) or any(p in ports for p in web_ports):
            return TargetType.WEB
        if any(kw in banner for kw in ["http", "nginx", "apache", "iis", "flask", "express"]):
            return TargetType.WEB

        # Network
        if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d+)?$", target):
            return TargetType.NETWORK
        if ports and not any(p in ports for p in web_ports):
            return TargetType.NETWORK

        return TargetType.UNKNOWN

    def detect_technologies(self, banners: list[str]) -> list[str]:
        tech_patterns = {
            "WordPress":    [r"wp-content", r"wp-includes", r"WordPress"],
            "Drupal":       [r"Drupal", r"/sites/default/"],
            "Joomla":       [r"Joomla", r"/components/com_"],
            "Django":       [r"csrfmiddlewaretoken", r"Django"],
            "Laravel":      [r"laravel_session", r"Laravel"],
            "React":        [r"react", r"__NEXT_DATA__"],
            "Angular":      [r"ng-version", r"angular"],
            "Vue":          [r"vue\.js", r"__vue__"],
            "PHP":          [r"\.php", r"X-Powered-By: PHP"],
            "ASP.NET":      [r"ASP\.NET", r"__VIEWSTATE"],
            "Spring":       [r"X-Application-Context", r"spring"],
            "Express":      [r"X-Powered-By: Express"],
            "Nginx":        [r"Server: nginx"],
            "Apache":       [r"Server: Apache"],
            "IIS":          [r"Server: Microsoft-IIS"],
            "Tomcat":       [r"Apache-Coyote", r"Tomcat"],
            "MySQL":        [r"MySQL", r"mysql"],
            "PostgreSQL":   [r"PostgreSQL", r"psql"],
            "MongoDB":      [r"MongoDB", r"mongo"],
            "Redis":        [r"Redis"],
            "GraphQL":      [r"graphql", r"__schema"],
            "JWT":          [r"eyJ[A-Za-z0-9_-]+\.eyJ"],
            "AWS":          [r"amazonaws\.com", r"X-Amz-"],
            "Cloudflare":   [r"cf-ray", r"cloudflare"],
        }
        found = []
        combined = " ".join(banners)
        for tech, patterns in tech_patterns.items():
            if any(re.search(p, combined, re.IGNORECASE) for p in patterns):
                found.append(tech)
        return found

    def detect_cloud_provider(self, target: str, banners: list[str]) -> str:
        combined = target + " " + " ".join(banners)
        if re.search(r"amazonaws|aws|s3\.", combined, re.IGNORECASE):
            return "AWS"
        if re.search(r"azure|azurewebsites|microsoft\.com/azure", combined, re.IGNORECASE):
            return "Azure"
        if re.search(r"googleapis|appspot|gcp|google\.cloud", combined, re.IGNORECASE):
            return "GCP"
        if re.search(r"digitalocean|linode|vultr", combined, re.IGNORECASE):
            return "VPS"
        return ""

    # ── Attack Surface Scoring ────────────────────────────────────────────────

    def score_attack_surface(self, profile: TargetProfile) -> float:
        score = 0.0
        # Ports
        score += min(len(profile.open_ports) * 0.3, 2.0)
        # Dangerous ports
        danger_ports = {21, 22, 23, 25, 53, 110, 111, 135, 139, 443, 445, 512, 513, 514,
                        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 27017}
        score += len(danger_ports & set(profile.open_ports)) * 0.2
        # Technologies (each adds attack surface)
        score += min(len(profile.technologies) * 0.15, 1.5)
        # CMS is high-value target
        if profile.cms:
            score += 1.0
        # Cloud misconfig surface
        if profile.cloud_provider:
            score += 0.8
        # Subdomains
        score += min(len(profile.subdomains) * 0.1, 1.0)
        # Endpoints
        score += min(len(profile.endpoints) * 0.05, 1.0)
        # Missing security headers
        expected_headers = {"X-Frame-Options", "Content-Security-Policy",
                            "X-Content-Type-Options", "Strict-Transport-Security"}
        missing = expected_headers - set(profile.security_headers.keys())
        score += len(missing) * 0.1
        return round(min(score, 10.0), 2)

    def determine_risk_level(self, surface_score: float, technologies: list[str]) -> RiskLevel:
        bonus = 0.0
        high_risk_tech = {"WordPress", "Drupal", "Joomla", "PHP", "ASP.NET", "MySQL"}
        bonus += len(high_risk_tech & set(technologies)) * 0.3

        total = surface_score + bonus
        if total >= 7.0:  return RiskLevel.CRITICAL
        if total >= 5.0:  return RiskLevel.HIGH
        if total >= 3.0:  return RiskLevel.MEDIUM
        if total >= 1.0:  return RiskLevel.LOW
        return RiskLevel.MINIMAL

    # ── Tool Selection ────────────────────────────────────────────────────────

    def select_optimal_tools(
        self,
        target_type: TargetType,
        objective: str = "comprehensive",
        top_n: int = 8,
    ) -> list[tuple[str, float]]:
        """Return (tool, effectiveness) sorted best-first for the given target type."""
        scores: list[tuple[str, float]] = []
        for tool, eff_map in TOOL_EFFECTIVENESS.items():
            eff = eff_map.get(target_type, 0.0)
            if eff > 0:
                scores.append((tool, eff))
        scores.sort(key=lambda x: x[1], reverse=True)

        if objective == "quick":
            return scores[:3]
        if objective == "stealth":
            stealth_tools = {"nmap", "masscan", "subfinder", "amass", "theharvester",
                             "wafw00f", "whatweb", "httpx"}
            return [(t, e) for t, e in scores if t in stealth_tools][:top_n]
        return scores[:top_n]

    # ── Parameter Optimization ────────────────────────────────────────────────

    def optimize_params(self, tool: str, profile: TargetProfile, flags: dict[str, Any] | None = None) -> dict[str, Any]:
        """Return optimized CLI parameters for a tool given the target profile."""
        flags = flags or {}
        method = f"_opt_{tool.replace('-', '_').replace('.', '_')}"
        fn = getattr(self, method, None)
        if fn:
            return fn(profile, flags)
        return {}

    def _opt_nmap(self, p: TargetProfile, f: dict) -> dict:
        if f.get("stealth"):
            return {"flags": "-sS -T2 -Pn --open", "reason": "stealth SYN scan"}
        if f.get("quick"):
            return {"flags": "-sV --top-ports 1000 -T4", "reason": "fast top-1000"}
        if p.target_type == TargetType.NETWORK:
            return {"flags": "-sV -sC -O -p- -T4 --open", "reason": "full network enum"}
        return {"flags": "-sV -sC --top-ports 3000 -T4 --open", "reason": "balanced scan"}

    def _opt_gobuster(self, p: TargetProfile, f: dict) -> dict:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if f.get("aggressive"):
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        ext = "php,html,txt,js,json"
        if "WordPress" in p.technologies:
            ext += ",wp,xml"
        return {"wordlist": wordlist, "extensions": ext, "threads": 50}

    def _opt_ffuf(self, p: TargetProfile, f: dict) -> dict:
        wordlist = "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-words.txt"
        rate = 500 if not f.get("stealth") else 50
        return {"wordlist": wordlist, "rate": rate, "mc": "200,204,301,302,307,401,403"}

    def _opt_nuclei(self, p: TargetProfile, f: dict) -> dict:
        tags = "cve,exposure,misconfig"
        if p.cms == "WordPress":
            tags += ",wordpress"
        if p.cloud_provider:
            tags += f",{p.cloud_provider.lower()}"
        severity = "critical,high,medium" if not f.get("quick") else "critical,high"
        return {"tags": tags, "severity": severity, "rate_limit": 150}

    def _opt_sqlmap(self, p: TargetProfile, f: dict) -> dict:
        level, risk = 2, 1
        if f.get("aggressive"):
            level, risk = 5, 3
        return {"level": level, "risk": risk, "flags": "--batch --random-agent --forms"}

    def _opt_hydra(self, p: TargetProfile, f: dict) -> dict:
        tasks = 16
        if 22 in p.open_ports:
            return {"service": "ssh", "tasks": tasks, "flags": "-V"}
        if 21 in p.open_ports:
            return {"service": "ftp", "tasks": tasks}
        if 3389 in p.open_ports:
            return {"service": "rdp", "tasks": 4}
        return {"service": "http-post-form", "tasks": tasks}

    def _opt_subfinder(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "-all -recursive", "timeout": 30}

    def _opt_amass(self, p: TargetProfile, f: dict) -> dict:
        if f.get("passive"):
            return {"flags": "intel -passive", "timeout": 60}
        return {"flags": "enum -active -brute", "timeout": 120}

    def _opt_nikto(self, p: TargetProfile, f: dict) -> dict:
        flags = "-Tuning 123bde"
        if 443 in p.open_ports:
            flags += " -ssl"
        return {"flags": flags, "timeout": 300}

    def _opt_wpscan(self, p: TargetProfile, f: dict) -> dict:
        return {
            "flags": "--enumerate u,p,t,tt --detection-mode aggressive",
            "reason": "enumerate users, plugins, themes"
        }

    def _opt_feroxbuster(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "--auto-tune --collect-words --collect-extensions", "threads": 50}

    def _opt_masscan(self, p: TargetProfile, f: dict) -> dict:
        rate = 10000 if not f.get("stealth") else 100
        return {"rate": rate, "ports": "0-65535", "flags": "--banners"}

    def _opt_rustscan(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "-a --ulimit 5000 --", "nmap_flags": "-sV -sC"}

    def _opt_prowler(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "-M csv,json -S", "checks": "high,critical"}

    def _opt_trivy(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "--severity HIGH,CRITICAL --format json"}

    def _opt_kube_hunter(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "--remote --report json"}

    def _opt_checkov(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "--output json --compact --check HIGH"}

    def _opt_gdb(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "-q", "commands": ["set disassembly-flavor intel", "run", "bt"]}

    def _opt_radare2(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "-A -q", "commands": ["afl", "pdf @main"]}

    def _opt_pwntools(self, p: TargetProfile, f: dict) -> dict:
        return {"arch": "amd64", "log_level": "debug"}

    def _opt_hashcat(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "-a 0 -m 0 --potfile-disable", "wordlist": "/usr/share/wordlists/rockyou.txt"}

    def _opt_john(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "--wordlist=/usr/share/wordlists/rockyou.txt --rules=best64"}

    def _opt_arjun(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "-m GET,POST --stable", "rate": 100}

    def _opt_dalfox(self, p: TargetProfile, f: dict) -> dict:
        return {"flags": "--skip-bav --waf-evasion --multicast", "timeout": 60}

    # ── Attack Chain Generation ───────────────────────────────────────────────

    def generate_attack_chain(
        self,
        target: str,
        target_type: TargetType | None = None,
        objective: str = "comprehensive",
        profile: TargetProfile | None = None,
    ) -> AttackChain:
        """Build a prioritised, step-by-step attack chain for the target."""
        if profile:
            tt = profile.target_type
        else:
            tt = target_type or self.detect_target_type(target)
            profile = TargetProfile(target=target, target_type=tt)

        chains = {
            TargetType.WEB:       self._chain_web,
            TargetType.API:       self._chain_api,
            TargetType.NETWORK:   self._chain_network,
            TargetType.CLOUD:     self._chain_cloud,
            TargetType.BINARY:    self._chain_binary,
            TargetType.CONTAINER: self._chain_container,
        }
        builder = chains.get(tt, self._chain_generic)
        chain = builder(target, profile, objective)
        chain.calculate_metrics()
        return chain

    def _chain_web(self, target: str, p: TargetProfile, obj: str) -> AttackChain:
        steps = [
            AttackStep(1, "whatweb",    f"detect technologies on {target}", "identify stack before testing", duration_est=15, success_prob=0.95),
            AttackStep(2, "wafw00f",    f"detect WAF on {target}", "know the WAF before fuzzing", duration_est=10, success_prob=0.90),
            AttackStep(3, "subfinder",  f"enumerate subdomains for {target}", "expand attack surface", duration_est=60, success_prob=0.85),
            AttackStep(4, "httpx",      f"probe live hosts from {target}", "filter live subdomains", duration_est=30, success_prob=0.92),
            AttackStep(5, "nikto",      f"vulnerability scan {target}", "find common vulns fast", duration_est=120, success_prob=0.80),
            AttackStep(6, "gobuster",   f"directory bust {target}", "discover hidden paths", params=self._opt_gobuster(p, {}), duration_est=90, success_prob=0.82),
            AttackStep(7, "nuclei",     f"template scan {target}", "match known CVEs and misconfigs", params=self._opt_nuclei(p, {}), duration_est=180, success_prob=0.88),
            AttackStep(8, "sqlmap",     f"test SQL injection on {target}", "critical injection testing", condition="if forms found", params=self._opt_sqlmap(p, {}), duration_est=120, success_prob=0.70),
            AttackStep(9, "dalfox",     f"XSS scan {target}", "reflected/stored XSS", condition="if forms found", duration_est=90, success_prob=0.65),
        ]
        if "WordPress" in p.technologies:
            steps.append(AttackStep(10, "wpscan", f"WordPress scan {target}", "WordPress-specific vulns", params=self._opt_wpscan(p, {}), duration_est=120, success_prob=0.90))
        return AttackChain("Web Application Attack Chain", TargetType.WEB, steps, RiskLevel.HIGH)

    def _chain_api(self, target: str, p: TargetProfile, obj: str) -> AttackChain:
        steps = [
            AttackStep(1, "httpx",         f"probe API endpoints at {target}", "fingerprint API", duration_est=20, success_prob=0.92),
            AttackStep(2, "arjun",         f"discover hidden parameters at {target}", "parameter pollution", params=self._opt_arjun(p, {}), duration_est=60, success_prob=0.80),
            AttackStep(3, "ffuf",          f"fuzz API endpoints at {target}", "endpoint discovery", params=self._opt_ffuf(p, {}), duration_est=90, success_prob=0.85),
            AttackStep(4, "jwt-analyzer",  f"analyse JWT tokens from {target}", "JWT misconfig", condition="if JWT detected", duration_est=15, success_prob=0.88),
            AttackStep(5, "sqlmap",        f"SQL injection on {target} API", "injection in params", params=self._opt_sqlmap(p, {}), duration_est=120, success_prob=0.72),
            AttackStep(6, "nuclei",        f"nuclei API scan {target}", "API-specific templates", params=self._opt_nuclei(p, {}), duration_est=120, success_prob=0.85),
        ]
        if "GraphQL" in p.technologies:
            steps.insert(2, AttackStep(2, "graphql-scanner", f"GraphQL introspection on {target}", "introspection + injection", duration_est=30, success_prob=0.85))
        return AttackChain("API Security Attack Chain", TargetType.API, steps, RiskLevel.HIGH)

    def _chain_network(self, target: str, p: TargetProfile, obj: str) -> AttackChain:
        steps = [
            AttackStep(1, "nmap",       f"full port scan {target}", "discover all open ports", params=self._opt_nmap(p, {}), duration_est=180, success_prob=0.95),
            AttackStep(2, "nmap",       f"service version scan {target}", "identify service versions", duration_est=120, success_prob=0.90),
            AttackStep(3, "enum4linux", f"SMB/RPC enumeration {target}", "windows enum", condition="if SMB found", duration_est=60, success_prob=0.85),
            AttackStep(4, "smbmap",     f"SMB share mapping {target}", "find accessible shares", condition="if SMB found", duration_est=30, success_prob=0.82),
            AttackStep(5, "nikto",      f"web vuln scan {target}", "web service scanning", condition="if HTTP found", params=self._opt_nikto(p, {}), duration_est=120, success_prob=0.78),
            AttackStep(6, "nuclei",     f"nuclei scan {target}", "CVE matching", params=self._opt_nuclei(p, {}), duration_est=180, success_prob=0.85),
            AttackStep(7, "hydra",      f"credential brute-force {target}", "weak passwords", condition="if login service found", params=self._opt_hydra(p, {}), duration_est=300, success_prob=0.45),
        ]
        return AttackChain("Network Penetration Attack Chain", TargetType.NETWORK, steps, RiskLevel.HIGH)

    def _chain_cloud(self, target: str, p: TargetProfile, obj: str) -> AttackChain:
        provider = p.cloud_provider or "AWS"
        steps = [
            AttackStep(1, "subfinder",   f"enumerate cloud subdomains {target}", "cloud asset discovery", duration_est=60, success_prob=0.85),
            AttackStep(2, "httpx",       f"probe cloud assets {target}", "live asset check", duration_est=30, success_prob=0.90),
            AttackStep(3, "nuclei",      f"cloud misconfiguration scan {target}", "S3 buckets, exposed services", params=self._opt_nuclei(p, {}), duration_est=180, success_prob=0.82),
            AttackStep(4, "prowler",     f"cloud security assessment {target}", "CIS benchmark check", condition="if AWS", params=self._opt_prowler(p, {}), duration_est=300, success_prob=0.88),
            AttackStep(5, "checkov",     f"IaC security scan", "infrastructure as code review", params=self._opt_checkov(p, {}), duration_est=60, success_prob=0.85),
            AttackStep(6, "trivy",       f"container/image scan {target}", "CVEs in images", params=self._opt_trivy(p, {}), duration_est=90, success_prob=0.88),
        ]
        return AttackChain(f"{provider} Cloud Attack Chain", TargetType.CLOUD, steps, RiskLevel.HIGH)

    def _chain_binary(self, target: str, p: TargetProfile, obj: str) -> AttackChain:
        steps = [
            AttackStep(1, "file",     f"identify binary type {target}", "architecture and format", duration_est=5, success_prob=0.99),
            AttackStep(2, "checksec", f"check binary protections {target}", "ASLR, NX, PIE, canary", duration_est=5, success_prob=0.98),
            AttackStep(3, "strings",  f"extract strings from {target}", "find hardcoded secrets", duration_est=10, success_prob=0.95),
            AttackStep(4, "binwalk",  f"analyse binary structure {target}", "embedded files/firmware", duration_est=30, success_prob=0.85),
            AttackStep(5, "radare2",  f"static analysis {target}", "disassembly and function map", params=self._opt_radare2(p, {}), duration_est=120, success_prob=0.82),
            AttackStep(6, "gdb",      f"dynamic analysis {target}", "runtime behaviour", params=self._opt_gdb(p, {}), duration_est=180, success_prob=0.75),
            AttackStep(7, "pwntools", f"exploit development {target}", "buffer overflow / ROP chain", condition="if vulnerable function found", params=self._opt_pwntools(p, {}), duration_est=300, success_prob=0.55),
        ]
        return AttackChain("Binary Exploitation Attack Chain", TargetType.BINARY, steps, RiskLevel.CRITICAL)

    def _chain_container(self, target: str, p: TargetProfile, obj: str) -> AttackChain:
        steps = [
            AttackStep(1, "trivy",       f"scan container image {target}", "known CVEs", params=self._opt_trivy(p, {}), duration_est=60, success_prob=0.90),
            AttackStep(2, "kube-hunter", f"Kubernetes penetration test {target}", "cluster misconfigs", params=self._opt_kube_hunter(p, {}), duration_est=120, success_prob=0.82),
            AttackStep(3, "checkov",     f"IaC misconfiguration scan", "Dockerfile and manifests", params=self._opt_checkov(p, {}), duration_est=60, success_prob=0.85),
            AttackStep(4, "nuclei",      f"container exposure scan {target}", "exposed dashboards and APIs", params=self._opt_nuclei(p, {}), duration_est=120, success_prob=0.80),
        ]
        return AttackChain("Container/Kubernetes Attack Chain", TargetType.CONTAINER, steps, RiskLevel.HIGH)

    def _chain_generic(self, target: str, p: TargetProfile, obj: str) -> AttackChain:
        steps = [
            AttackStep(1, "nmap",      f"port scan {target}", "initial reconnaissance", params=self._opt_nmap(p, {"quick": True}), duration_est=60, success_prob=0.95),
            AttackStep(2, "nuclei",    f"vulnerability scan {target}", "template-based detection", params=self._opt_nuclei(p, {}), duration_est=180, success_prob=0.80),
            AttackStep(3, "nikto",     f"web scan {target}", "common vulnerabilities", condition="if HTTP found", duration_est=120, success_prob=0.75),
        ]
        return AttackChain("Generic Reconnaissance Chain", TargetType.UNKNOWN, steps, RiskLevel.LOW)

    # ── Full Profile ──────────────────────────────────────────────────────────

    def build_profile(
        self,
        target: str,
        open_ports: list[int] | None = None,
        services: dict[int, str] | None = None,
        banners: list[str] | None = None,
        subdomains: list[str] | None = None,
        endpoints: list[str] | None = None,
        security_headers: dict[str, str] | None = None,
    ) -> TargetProfile:
        ports    = open_ports or []
        svcs     = services or {}
        bnrs     = banners or []
        context  = {"open_ports": ports, "services": svcs}

        tt      = self.detect_target_type(target, context)
        techs   = self.detect_technologies(bnrs)
        cloud   = self.detect_cloud_provider(target, bnrs)
        cms     = next((t for t in techs if t in {"WordPress", "Drupal", "Joomla"}), "")

        profile = TargetProfile(
            target=target,
            target_type=tt,
            open_ports=ports,
            services=svcs,
            technologies=techs,
            cms=cms,
            cloud_provider=cloud,
            subdomains=subdomains or [],
            endpoints=endpoints or [],
            security_headers=security_headers or {},
        )
        profile.attack_surface = self.score_attack_surface(profile)
        profile.risk_level     = self.determine_risk_level(profile.attack_surface, techs)
        profile.confidence     = min(0.3 + len(ports) * 0.05 + len(techs) * 0.08, 1.0)
        profile.flags = {
            "has_web":   any(p in ports for p in [80, 443, 8080, 8443]),
            "has_smb":   445 in ports or 139 in ports,
            "has_ssh":   22 in ports,
            "has_db":    any(p in ports for p in [3306, 5432, 1433, 27017, 6379]),
            "has_rdp":   3389 in ports,
            "is_cms":    bool(cms),
            "is_cloud":  bool(cloud),
        }
        return profile
