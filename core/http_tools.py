from __future__ import annotations

import html.parser
import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import httpx


SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


class LinkParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {k.lower(): v or "" for k, v in attrs}
        if tag == "a" and data.get("href"):
            self.links.append(data["href"])
        elif tag == "script" and data.get("src"):
            self.scripts.append(data["src"])
        elif tag == "form":
            self._form = {
                "method": data.get("method", "get").upper(),
                "action": data.get("action", ""),
                "inputs": [],
            }
        elif tag in {"input", "textarea", "select"} and self._form is not None:
            self._form["inputs"].append({
                "name": data.get("name", ""),
                "type": data.get("type", tag),
                "value": data.get("value", ""),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _same_origin(url: str, base: str) -> bool:
    parsed = urlparse(url)
    root = urlparse(base)
    return parsed.scheme in {"http", "https"} and parsed.netloc == root.netloc


def _parse_html(content: str) -> LinkParser:
    parser = LinkParser()
    parser.feed(content)
    return parser


def _security_analysis(url: str, headers: httpx.Headers, body: str) -> dict[str, Any]:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing = [header for header in SECURITY_HEADERS if header not in lower_headers]
    cookies = headers.get_list("set-cookie")
    cookie_issues = []
    for cookie in cookies:
        cookie_lower = cookie.lower()
        if "httponly" not in cookie_lower:
            cookie_issues.append("cookie missing HttpOnly")
        if url.startswith("https://") and "secure" not in cookie_lower:
            cookie_issues.append("HTTPS cookie missing Secure")
        if "samesite" not in cookie_lower:
            cookie_issues.append("cookie missing SameSite")

    exposed = []
    if re.search(r"AKIA[0-9A-Z]{16}", body):
        exposed.append("possible AWS access key pattern")
    if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", body):
        exposed.append("possible private key")
    if re.search(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]{12,}", body):
        exposed.append("possible secret/token literal")

    score = max(0, 100 - (len(missing) * 6) - (len(cookie_issues) * 4) - (len(exposed) * 20))
    return {
        "missing_security_headers": missing,
        "cookie_issues": sorted(set(cookie_issues)),
        "exposed_secret_indicators": exposed,
        "security_score": score,
    }


def http_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    timeout: float = 15.0,
) -> dict[str, Any]:
    started = time.time()
    method = method.upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        return {"success": False, "error": "read-only HTTP helper only allows GET, HEAD, and OPTIONS"}

    try:
        with httpx.Client(follow_redirects=True, timeout=timeout) as client:
            response = client.request(method, url, headers=headers or {}, params=data if method == "GET" else None)
    except httpx.HTTPError as exc:
        return {"success": False, "url": url, "error": str(exc)}

    text = response.text[:200000]
    parser = _parse_html(text)
    return {
        "success": True,
        "url": str(response.url),
        "status_code": response.status_code,
        "headers": dict(response.headers),
        "elapsed": round(time.time() - started, 3),
        "title": _extract_title(text),
        "links": [urljoin(str(response.url), link) for link in parser.links[:200]],
        "scripts": [urljoin(str(response.url), src) for src in parser.scripts[:100]],
        "forms": parser.forms[:50],
        "security": _security_analysis(str(response.url), response.headers, text),
        "body_sample": text[:5000],
    }


def crawl_site(start_url: str, max_pages: int = 25, max_depth: int = 2) -> dict[str, Any]:
    seen: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    pages = []

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen or depth > max_depth:
            continue
        seen.add(url)
        result = http_request(url)
        if not result.get("success"):
            pages.append({"url": url, "error": result.get("error")})
            continue
        pages.append({
            "url": result["url"],
            "status_code": result["status_code"],
            "title": result["title"],
            "forms": len(result["forms"]),
            "links": len(result["links"]),
            "security_score": result["security"]["security_score"],
        })
        for link in result["links"]:
            normalized = _strip_fragment(link)
            if normalized not in seen and _same_origin(normalized, start_url):
                queue.append((normalized, depth + 1))

    return {"success": True, "start_url": start_url, "pages": pages, "total_pages": len(pages)}


def browser_inspect(url: str) -> dict[str, Any]:
    result = http_request(url)
    if not result.get("success"):
        return result
    technologies = []
    headers = {k.lower(): v.lower() for k, v in result["headers"].items()}
    body = result["body_sample"].lower()
    server = headers.get("server", "")
    powered = headers.get("x-powered-by", "")
    if server:
        technologies.append(server)
    if powered:
        technologies.append(powered)
    for name, marker in {
        "WordPress": "wp-content",
        "React/Next": "__next_data__",
        "Vue": "vue",
        "Angular": "ng-version",
        "jQuery": "jquery",
        "Bootstrap": "bootstrap",
    }.items():
        if marker in body:
            technologies.append(name)
    return {
        "success": True,
        "url": result["url"],
        "status_code": result["status_code"],
        "title": result["title"],
        "technologies": sorted(set(technologies)),
        "forms": result["forms"],
        "scripts": result["scripts"],
        "security": result["security"],
        "notes": "Static browser-like inspection. JavaScript rendering is not enabled.",
    }


def intruder_sniper(
    url: str,
    parameter: str,
    payloads: list[str],
    max_requests: int = 50,
) -> dict[str, Any]:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if parameter not in query:
        query[parameter] = ""
    rows = []
    for payload in payloads[:max_requests]:
        query[parameter] = payload
        test_url = urlunparse(parsed._replace(query=urlencode(query)))
        result = http_request(test_url)
        rows.append({
            "payload": payload,
            "status_code": result.get("status_code"),
            "length": len(result.get("body_sample", "")),
            "reflected": payload in result.get("body_sample", ""),
            "url": test_url,
        })
    return {"success": True, "url": url, "parameter": parameter, "results": rows}


def _strip_fragment(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _extract_title(text: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]
