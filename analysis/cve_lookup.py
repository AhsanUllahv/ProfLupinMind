import re
import time
import requests
from typing import List, Dict

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_CACHE_TTL = 3600  # 1 hour
_cache: Dict[str, tuple] = {}  # keyword → (cached_at, results)

# Patterns to extract software+version strings from tool output
_VERSION_PATTERNS = [
    r"(Apache(?:[\s/][\d.]+))",
    r"(nginx(?:[\s/][\d.]+))",
    r"(OpenSSH(?:[_\s/][\d.p]+))",
    r"(vsftpd(?:[\s/][\d.]+))",
    r"(Samba(?:[\s/][\d.]+))",
    r"(PHP(?:[\s/][\d.]+))",
    r"(WordPress(?:[\s/][\d.]+))",
    r"(Drupal(?:[\s/][\d.]+))",
    r"(Joomla(?:[!\s/][\d.]+))",
    r"(IIS(?:[\s/][\d.]+))",
    r"(Tomcat(?:[\s/][\d.]+))",
    r"(MySQL(?:[\s/][\d.]+))",
    r"(PostgreSQL(?:[\s/][\d.]+))",
    r"(ProFTPD(?:[\s/][\d.]+))",
    r"(Exim(?:[\s/][\d.]+))",
    r"(Postfix(?:[\s/][\d.]+))",
    r"(OpenSSL(?:[\s/][\d.a-z]+))",
    r"(Lighttpd(?:[\s/][\d.]+))",
    r"(Redis(?:[\s/][\d.]+))",
    r"(MongoDB(?:[\s/][\d.]+))",
]


def extract_software_from_output(text: str) -> List[str]:
    """Pull software+version tokens out of raw tool output."""
    found = set()
    for pattern in _VERSION_PATTERNS:
        for match in re.findall(pattern, text, re.IGNORECASE):
            found.add(match.strip())
    return list(found)


def _query_nvd(keyword: str, max_results: int = 5) -> List[Dict]:
    """Query NVD API for CVEs matching a keyword. Returns list of CVE dicts."""
    now = time.time()
    if keyword in _cache:
        cached_at, results = _cache[keyword]
        if now - cached_at < _CACHE_TTL:
            return results

    try:
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": max_results},
            timeout=10,
            headers={"User-Agent": "lupin-mind/1.0"},
        )
        if resp.status_code != 200:
            return []

        items = resp.json().get("vulnerabilities", [])
        results = []

        for item in items:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue

            # English description
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "No description available.",
            )

            # Severity from CVSSv3 → v2 fallback
            metrics = cve.get("metrics", {})
            severity, score = "UNKNOWN", None

            cvss3 = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
            if cvss3:
                d = cvss3[0].get("cvssData", {})
                severity = d.get("baseSeverity", "UNKNOWN")
                score = d.get("baseScore")
            elif metrics.get("cvssMetricV2"):
                d = metrics["cvssMetricV2"][0].get("cvssData", {})
                score = d.get("baseScore")
                if score is not None:
                    severity = "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"

            results.append({
                "id": cve_id,
                "description": desc[:250],
                "severity": severity,
                "score": score,
                "keyword": keyword,
            })

        _cache[keyword] = (time.time(), results)
        # NVD public rate limit: 5 requests per 30s — be polite
        time.sleep(0.7)
        return results

    except Exception:
        return []


def lookup_cves_from_output(output: str, max_queries: int = 3) -> List[Dict]:
    """
    Scan raw tool output for software versions, query NVD for each,
    and return a deduplicated list of CVE dicts sorted by score.
    """
    queries = extract_software_from_output(output)
    all_cves: List[Dict] = []
    seen_ids: set = set()

    for q in queries[:max_queries]:
        for cve in _query_nvd(q):
            if cve["id"] not in seen_ids:
                seen_ids.add(cve["id"])
                all_cves.append(cve)

    # Sort: highest score first, unknowns last
    all_cves.sort(key=lambda c: c.get("score") or 0, reverse=True)
    return all_cves


def severity_to_finding_severity(cve_severity: str) -> str:
    """Map NVD severity string to our internal severity tag."""
    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }
    return mapping.get(cve_severity.upper(), "INFO")
