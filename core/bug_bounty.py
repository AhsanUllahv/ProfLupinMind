"""
Bug Bounty Manager — structured recon, OSINT, vulnerability hunting,
file upload testing, authentication bypass, and business logic workflows.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


# ─── Impact Ratings ───────────────────────────────────────────────────────────

VULN_IMPACT: dict[str, int] = {
    "RCE":                      10,
    "SQL Injection":             9,
    "SSRF":                      8,
    "IDOR":                      8,
    "Auth Bypass":               8,
    "XXE":                       7,
    "SSTI":                      9,
    "Privilege Escalation":      9,
    "Path Traversal":            7,
    "File Upload RCE":           10,
    "Open Redirect":             5,
    "XSS (Stored)":              7,
    "XSS (Reflected)":           5,
    "CSRF":                      6,
    "Business Logic":            7,
    "Info Disclosure":           4,
    "Subdomain Takeover":        7,
    "Account Takeover":          9,
    "Broken Auth":               8,
    "Insecure Deserialization":  9,
    "JWT Misconfiguration":      8,
    "CORS Misconfiguration":     7,
    "HTTP Request Smuggling":    8,
    "CRLF Injection":            6,
    "Secret Leak":               8,
    "Race Condition":            7,
    "GraphQL Injection":         8,
    "Host Header Injection":     6,
    "OAuth Misconfiguration":    8,
}

# ─── Workflow Step ────────────────────────────────────────────────────────────

@dataclass
class BBStep:
    phase:       str
    tool:        str
    goal:        str
    reason:      str
    options:     str = ""
    condition:   str = "always"
    priority:    str = "high"   # high / medium / low


@dataclass
class BugBountyWorkflow:
    name:        str
    phases:      list[str]
    steps:       list[BBStep]
    target_vulns: list[str] = field(default_factory=list)
    notes:       list[str]  = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name":         self.name,
            "phases":       self.phases,
            "target_vulns": self.target_vulns,
            "step_count":   len(self.steps),
            "steps": [
                {
                    "phase":     s.phase,
                    "tool":      s.tool,
                    "goal":      s.goal,
                    "reason":    s.reason,
                    "options":   s.options,
                    "condition": s.condition,
                    "priority":  s.priority,
                }
                for s in self.steps
            ],
            "notes": self.notes,
        }


# ─── Bug Bounty Manager ───────────────────────────────────────────────────────

class BugBountyManager:

    # ── Reconnaissance ────────────────────────────────────────────────────────

    def recon_workflow(self, target: str) -> BugBountyWorkflow:
        return BugBountyWorkflow(
            name="Bug Bounty Reconnaissance",
            phases=["passive_recon", "active_recon", "asset_discovery", "fingerprinting", "secrets_hunt"],
            steps=[
                # Passive
                BBStep("passive_recon", "subfinder",    f"enumerate all subdomains for {target}", "expand attack surface before active testing", "-all -recursive -silent", priority="high"),
                BBStep("passive_recon", "amass",        f"deep subdomain intelligence for {target}", "amass catches subdomains subfinder misses", "enum -passive", priority="high"),
                BBStep("passive_recon", "theHarvester", f"gather emails and DNS records for {target}", "emails useful for social engineering context", f"-d {target} -b all"),
                BBStep("passive_recon", "waybackurls",  f"fetch historical URLs for {target}", "old endpoints may still be active"),
                BBStep("passive_recon", "gau",          f"gather known URLs for {target} from all sources", "AlienVault, Wayback, Common Crawl"),
                # Active
                BBStep("active_recon",  "httpx",        f"probe all discovered subdomains of {target}", "filter live hosts before scanning", f"-u https://{target} -status-code -title -tech-detect -no-color", priority="high"),
                BBStep("active_recon",  "gowitness",    f"screenshot all live hosts of {target}", "visual recon — spot admin panels and login pages at a glance"),
                BBStep("active_recon",  "nmap",         f"port scan live hosts of {target}", "identify non-standard services", "-sV --top-ports 1000 -T4"),
                BBStep("active_recon",  "wafw00f",      f"detect WAF on {target}", "adapt payloads to WAF", f"https://{target}"),
                # Asset Discovery
                BBStep("asset_discovery", "feroxbuster", f"directory and file discovery on {target}", "find hidden content", f"-u https://{target} -w /usr/share/wordlists/dirb/common.txt --depth 2 -q"),
                BBStep("asset_discovery", "katana",     f"crawl {target} for all endpoints", "full attack surface mapping", f"-u https://{target} -d 5 -jc -silent"),
                BBStep("asset_discovery", "arjun",      f"discover hidden parameters on {target}", "parameter pollution and SSRF entry points", f"-u https://{target}"),
                BBStep("asset_discovery", "gau",        f"find js files and API endpoints for {target}", "extract endpoints from JS files"),
                BBStep("asset_discovery", "gobuster",   f"directory bruteforce on {target}", "find hidden paths", f"dir -u https://{target} -w /usr/share/wordlists/dirb/common.txt -x php,html,js -t 30 -q -b 301,302"),
                BBStep("asset_discovery", "meg",        f"probe common sensitive paths on all {target} hosts", "low-bandwidth bulk path testing", "-d 1000 -v"),
                # Fingerprinting
                BBStep("fingerprinting", "whatweb",     f"fingerprint technologies on {target}", "identify exact versions for CVE lookup"),
                BBStep("fingerprinting", "nuclei",      f"technology-specific template scan {target}", "detect version-specific CVEs", f"-u https://{target} -tags tech,exposure -silent"),
                # Secrets Hunt
                BBStep("secrets_hunt",   "nuclei",      f"scan for exposed secrets and misconfigs on {target}", "API keys and tokens in JS — direct account compromise", f"-u https://{target} -tags exposure,token,secret,config -silent"),
                BBStep("secrets_hunt",   "trufflehog",  f"scan {target} public repos for leaked secrets", "credentials accidentally committed to GitHub", condition="if github org known"),
                BBStep("secrets_hunt",   "gitdumper",   f"download exposed .git from {target}", "full source code from misconfigured server", condition="if /.git/ returns 200"),
            ],
            target_vulns=["Subdomain Takeover", "Info Disclosure", "Exposed Admin Panels", "Secret Leak"],
            notes=[
                "Always check for dangling DNS / subdomain takeover",
                "Look for staging/dev subdomains — often less hardened",
                "JS files often contain API keys and hidden endpoints",
                "Check .git/, .env, backup.zip on every discovered host",
                "Use interactsh-client for blind SSRF/XXE OOB callbacks",
                "Filter gau+waybackurls output with gf patterns (xss, ssrf, sqli)",
            ],
        )

    # ── OSINT ─────────────────────────────────────────────────────────────────

    def osint_workflow(self, target: str) -> BugBountyWorkflow:
        return BugBountyWorkflow(
            name="Bug Bounty OSINT",
            phases=["identity", "infrastructure", "leaks", "social"],
            steps=[
                BBStep("identity",        "theHarvester", f"harvest emails and names for {target}", "identify employees for phishing or password guessing", f"-d {target} -b all"),
                BBStep("identity",        "sherlock",     f"find social media for {target} employees", "linkedin, twitter, github enumeration", condition="if username known"),
                BBStep("infrastructure",  "amass",        f"map infrastructure for {target}", "autonomous system and IP range discovery", "intel -whois"),
                BBStep("infrastructure",  "subfinder",    f"enumerate subdomains for {target}", "full subdomain map"),
                BBStep("leaks",           "theHarvester", f"search for data leaks related to {target}", "breach databases and pastebin", f"-d {target} -b all"),
                BBStep("social",          "spiderfoot",   f"automated OSINT collection for {target}", "comprehensive automated OSINT"),
            ],
            target_vulns=["Info Disclosure", "Account Takeover", "Credential Stuffing"],
            notes=[
                "Check GitHub for leaked API keys: site:github.com {target}",
                "Search Shodan for exposed services: org:{target}",
                "Certificate transparency: crt.sh for subdomain discovery",
                "LinkedIn employee names → password spray targets",
            ],
        )

    # ── Vulnerability Hunting ─────────────────────────────────────────────────

    def vuln_hunting_workflow(self, target: str) -> BugBountyWorkflow:
        return BugBountyWorkflow(
            name="Bug Bounty Vulnerability Hunting",
            phases=["automated_scan", "injection_testing", "auth_testing", "access_control", "advanced"],
            steps=[
                # Automated scanning
                BBStep("automated_scan",  "nuclei",       f"full vulnerability template scan {target}", "quick win — matches known CVEs and misconfigs", "-severity critical,high,medium -rate-limit 150", priority="high"),
                BBStep("automated_scan",  "nikto",        f"web vulnerability scan {target}", "catches common misconfigurations quickly"),
                BBStep("automated_scan",  "wpscan",       f"WordPress vulnerability scan {target}", "WordPress-specific CVEs", condition="if WordPress detected"),
                # Injection
                BBStep("injection_testing","sqlmap",      f"SQL injection test {target}", "automated SQLi with forms crawling", "--batch --forms --level=3 --risk=2 --random-agent"),
                BBStep("injection_testing","dalfox",      f"XSS scan {target}", "reflected, stored, DOM XSS", "--skip-bav --waf-evasion"),
                BBStep("injection_testing","gf",          f"filter URL params for injection patterns on {target}", "rapid triage of large URL sets", "xss | gf sqli | gf ssrf"),
                BBStep("injection_testing","ffuf",        f"fuzz all parameters on {target}", "discover injection points and hidden params", "-mc 200,301,302,400,403,500"),
                BBStep("injection_testing","crlfuzz",     f"CRLF injection test {target}", "header injection and response splitting", condition="if URL params present"),
                BBStep("injection_testing","smuggler",    f"HTTP request smuggling test on {target}", "CL.TE and TE.CL desync vulnerabilities"),
                # Auth
                BBStep("auth_testing",    "jwt-analyzer", f"analyse JWT tokens from {target}", "check weak secrets, alg:none, key confusion", condition="if JWT found"),
                BBStep("auth_testing",    "hydra",        f"credential brute-force on {target} login", "test common/default credentials", condition="if login form found"),
                BBStep("auth_testing",    "interactsh-client", f"start OOB listener for blind injection testing {target}", "catch blind SSRF/XXE/RCE callbacks"),
                # Access Control
                BBStep("access_control",  "ffuf",         f"fuzz object IDs for IDOR on {target}", "horizontal privilege escalation", condition="if authenticated endpoints found"),
                BBStep("access_control",  "nuclei",       f"IDOR and auth bypass templates on {target}", "automated access control checks", "-tags idor,auth-bypass"),
                # Advanced
                BBStep("advanced",        "corsy",        f"CORS misconfiguration scan on {target}", "cross-origin data theft"),
                BBStep("advanced",        "graphql_scanner", f"GraphQL security test on {target}", "introspection, injection, batching abuse", condition="if GraphQL endpoint found"),
                BBStep("advanced",        "nuclei",       f"SSRF template scan on {target}", "AWS metadata, internal service discovery", "-tags ssrf,oast"),
            ],
            target_vulns=list(VULN_IMPACT.keys())[:12],
            notes=[
                "Always authenticate before testing authenticated endpoints",
                "Test parameter pollution: ?id=1&id=2",
                "Check HTTP method switching: GET → POST, POST → PUT",
                "Mass assignment: send extra fields in JSON body",
                "Use interactsh for all blind SSRF/XXE/SSTI payloads",
                "CORS: test Origin: https://evil.com and Origin: null",
                "Smuggling: use Burp HTTP Request Smuggler or smuggler.py",
                "Rate limiting bypass: X-Forwarded-For, X-Real-IP header rotation",
            ],
        )

    # ── File Upload Testing ───────────────────────────────────────────────────

    def file_upload_workflow(self, target: str) -> BugBountyWorkflow:
        return BugBountyWorkflow(
            name="File Upload Security Testing",
            phases=["discovery", "extension_bypass", "content_bypass", "execution_test"],
            steps=[
                BBStep("discovery",         "gobuster",  f"find upload endpoints on {target}", "locate file upload functionality", "-x php,html,js --status-codes 200,301,302"),
                BBStep("discovery",         "katana",    f"crawl {target} for upload forms", "find all upload inputs"),
                BBStep("extension_bypass",  "ffuf",      f"fuzz file extensions on {target} upload endpoint", "double extension, MIME bypass", condition="if upload endpoint found"),
                BBStep("content_bypass",    "curl",      f"upload files with crafted Content-Type to {target}", "content-type spoofing test", condition="if upload endpoint found"),
                BBStep("execution_test",    "gobuster",  f"find uploaded file on {target}", "confirm execution after upload", condition="if upload succeeded"),
                BBStep("execution_test",    "nuclei",    f"test upload security on {target}", "template-based upload bypass detection", "-tags upload"),
            ],
            target_vulns=["File Upload RCE", "Path Traversal", "IDOR"],
            notes=[
                "Always test: .php, .phtml, .php5, .phar, .php.jpg extensions",
                "Try null byte: shell.php%00.jpg",
                "Test Content-Type: image/jpeg with PHP body",
                "Prepend GIF89a to PHP webshell (magic bytes bypass)",
                "Try uploading SVG with XSS payload",
                "Test path traversal in filename: ../../../shell.php",
            ],
        )

    # ── Authentication Bypass ─────────────────────────────────────────────────

    def auth_bypass_workflow(self, target: str) -> BugBountyWorkflow:
        return BugBountyWorkflow(
            name="Authentication Bypass Testing",
            phases=["enum", "bypass", "session", "mfa"],
            steps=[
                BBStep("enum",    "ffuf",         f"enumerate users on {target}", "user enumeration via timing/response", "--mc 200,302 --fs 0"),
                BBStep("enum",    "hydra",        f"test default credentials on {target}", "admin:admin, admin:password, etc.", "-L /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/SecLists/Passwords/darkweb2017-top100.txt"),
                BBStep("bypass",  "sqlmap",       f"SQLi authentication bypass on {target}", "' OR '1'='1 and variants", "--technique=B --forms"),
                BBStep("bypass",  "jwt-analyzer", f"JWT bypass testing on {target}", "alg:none, weak secret, key confusion", condition="if JWT found"),
                BBStep("bypass",  "ffuf",         f"test password reset on {target}", "host header injection, weak tokens", "-mc 200,302", condition="if password reset exists"),
                BBStep("session", "nuclei",       f"session security test on {target}", "session fixation, weak cookies", "-tags session,cookie"),
                BBStep("mfa",     "ffuf",         f"MFA bypass on {target}", "response manipulation, backup code brute-force", condition="if MFA present"),
            ],
            target_vulns=["Auth Bypass", "Account Takeover", "Broken Auth", "JWT Misconfiguration"],
            notes=[
                "Try SQL injection: ' OR 1=1-- as username",
                "Test password reset: manipulate Host header",
                "JWT: change alg to none, remove signature",
                "MFA: try response manipulation (change 'success': false to true)",
                "Check for account lockout bypass: X-Forwarded-For rotation",
                "Test OAuth flows for state parameter and redirect_uri bypass",
            ],
        )

    # ── Business Logic Testing ────────────────────────────────────────────────

    def business_logic_workflow(self, target: str) -> BugBountyWorkflow:
        return BugBountyWorkflow(
            name="Business Logic Testing",
            phases=["workflow_analysis", "parameter_manipulation", "race_conditions", "privilege"],
            steps=[
                BBStep("workflow_analysis",    "katana",  f"crawl {target} for all workflow pages", "map all multi-step processes"),
                BBStep("workflow_analysis",    "nuclei",  f"business logic template scan {target}", "detect common logic flaws", "-tags logic,workflow"),
                BBStep("parameter_manipulation","ffuf",   f"parameter manipulation on {target}", "negative prices, skip steps", condition="if e-commerce or multi-step"),
                BBStep("race_conditions",      "ffuf",    f"race condition test on {target}", "concurrent requests to same endpoint", "-rate 0 -t 100", condition="if purchase/credit flow"),
                BBStep("privilege",            "nuclei",  f"privilege escalation test {target}", "horizontal and vertical access", "-tags priv-esc,idor"),
            ],
            target_vulns=["Business Logic", "IDOR", "Race Condition", "Privilege Escalation"],
            notes=[
                "Test negative values: price=-100 in cart",
                "Skip payment step by manipulating flow",
                "Race conditions: Turbo Intruder for concurrent requests",
                "Try accessing other users' order IDs",
                "Test coupon codes: apply same code multiple times",
                "Mass assignment: send admin=true in registration",
            ],
        )

    # ── High-Impact Finding Checklist ─────────────────────────────────────────

    def high_impact_checklist(self, target: str) -> dict[str, Any]:
        """Return a prioritised checklist of high-impact tests ordered by severity."""
        checks = sorted(VULN_IMPACT.items(), key=lambda x: x[1], reverse=True)
        return {
            "target":   target,
            "checklist": [
                {
                    "vuln":   vuln,
                    "impact": score,
                    "test":   self._get_quick_test(vuln),
                }
                for vuln, score in checks
            ],
        }

    def _get_quick_test(self, vuln: str) -> str:
        tests: dict[str, str] = {
            "RCE":                 "Inject ; id in all inputs, check for command output",
            "SQL Injection":       "Inject ' and observe error or timing change",
            "SSRF":                "Set url= to http://169.254.169.254/ or http://attacker.com",
            "IDOR":                "Change numeric IDs in API responses",
            "Auth Bypass":         "SQL: ' OR '1'='1, JWT alg:none, default creds",
            "XXE":                 "Submit XML with <!DOCTYPE> external entity",
            "SSTI":                "Inject {{7*7}} in template fields",
            "File Upload RCE":     "Upload .php with double extension, content-type bypass",
            "Open Redirect":            "Set redirect= to //evil.com",
            "XSS (Stored)":             "Inject <script>alert(1)</script> in persisted fields",
            "XSS (Reflected)":          "Inject <script>alert(1)</script> in URL params",
            "CSRF":                     "Check for SameSite cookie and CSRF token presence",
            "Subdomain Takeover":       "Check CNAME for unclaimed cloud services",
            "Account Takeover":         "Test password reset flow, OAuth, and session handling",
            "JWT Misconfiguration":     "Check alg, weak secret, kid injection",
            "Insecure Deserialization": "Identify serialized objects, use ysoserial",
            "Privilege Escalation":     "Access admin endpoints without admin role",
            "Path Traversal":           "Inject ../../../etc/passwd in file parameters",
            "Business Logic":           "Skip workflow steps, use negative values, race conditions",
            "Info Disclosure":          "Check error messages, .env, .git, backup files",
            "Broken Auth":              "Brute-force, account lockout bypass, weak tokens",
            "CORS Misconfiguration":    "Set Origin: https://evil.com — check ACAO header reflects it",
            "HTTP Request Smuggling":   "CL.TE: Content-Length+Transfer-Encoding desync with smuggler.py",
            "CRLF Injection":           "Inject %0d%0a in URL params, check for injected headers",
            "Secret Leak":              "Scan JS files with secretfinder, check .env and git history",
            "Race Condition":           "Send 20+ concurrent requests to single-use endpoints",
            "GraphQL Injection":        "Test introspection, batch queries, field-level injection",
            "Host Header Injection":    "Set Host: evil.com, check password reset email links",
            "OAuth Misconfiguration":   "Test redirect_uri wildcard bypass, state param CSRF, implicit flow",
        }
        return tests.get(vuln, "Manual testing required")

    def get_workflow(self, workflow_name: str, target: str) -> BugBountyWorkflow | None:
        workflows: dict[str, Any] = {
            "recon":          self.recon_workflow,
            "reconnaissance": self.recon_workflow,
            "osint":          self.osint_workflow,
            "vuln_hunting":   self.vuln_hunting_workflow,
            "vulnerability":  self.vuln_hunting_workflow,
            "file_upload":    self.file_upload_workflow,
            "upload":         self.file_upload_workflow,
            "auth_bypass":    self.auth_bypass_workflow,
            "auth":           self.auth_bypass_workflow,
            "business_logic": self.business_logic_workflow,
            "logic":          self.business_logic_workflow,
        }
        fn = workflows.get(workflow_name.lower())
        return fn(target) if fn else None

    def list_workflows(self) -> list[dict[str, str]]:
        return [
            {"name": "recon",          "description": "Full passive + active reconnaissance"},
            {"name": "osint",          "description": "OSINT, email/subdomain gathering, leaks"},
            {"name": "vuln_hunting",   "description": "Automated + manual vulnerability hunting"},
            {"name": "file_upload",    "description": "File upload security and bypass testing"},
            {"name": "auth_bypass",    "description": "Authentication and session bypass testing"},
            {"name": "business_logic", "description": "Business logic and race condition testing"},
        ]
