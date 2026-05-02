import ipaddress
import re
import shlex
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
_FILE_EXT_RE = re.compile(
    r"\.(py|sh|pl|rb|js|ts|html|htm|php|txt|json|xml|yaml|yml|conf|cfg|sql|"
    r"zip|tar|gz|log|md|csv|pdf|png|jpg|jpeg|gif|svg|woff|ttf|eot|map)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScopeViolation:
    target: str
    reason: str


def normalize_scope(scope: Iterable[str]) -> list[str]:
    """Return trimmed, de-duplicated scope entries."""
    normalized: list[str] = []
    for item in scope:
        value = str(item).strip().lower()
        if value and value not in normalized:
            normalized.append(value)
    return normalized


def is_in_scope(target: str, scope: Iterable[str]) -> bool:
    """Check whether an IP, CIDR, domain, or URL target is inside scope."""
    host = _target_host(target)
    if not host:
        return True

    host = host.lower().strip("[]")
    scope_items = normalize_scope(scope)
    if not scope_items:
        return False

    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None
    try:
        host_network = ipaddress.ip_network(host, strict=False)
    except ValueError:
        host_network = None

    for item in scope_items:
        scope_host = _target_host(item) or item
        scope_host = scope_host.lower().strip("[]")

        try:
            network = ipaddress.ip_network(scope_host, strict=False)
            if host_network and host_network.subnet_of(network):
                return True
            if host_ip and host_ip in network:
                return True
            continue
        except ValueError:
            pass

        if host == scope_host:
            return True

        # A scoped domain also permits its subdomains.
        if _DOMAIN_RE.match(scope_host) and host.endswith(f".{scope_host}"):
            return True

    return False


def find_scope_violations(command: str, scope: Iterable[str]) -> list[ScopeViolation]:
    """Extract network-ish targets from a command and report out-of-scope values."""
    violations: list[ScopeViolation] = []
    for target in extract_command_targets(command):
        if not is_in_scope(target, scope):
            violations.append(
                ScopeViolation(target=target, reason="target is outside the locked scope")
            )
    return violations


def extract_command_targets(command: str) -> list[str]:
    """
    Pull likely remote targets from a shell command.

    This intentionally ignores filesystem paths and common option values so local
    wordlists, output files, and scripts do not trip the scope gate.
    """
    targets: list[str] = []

    for url in re.findall(r"\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+", command, re.IGNORECASE):
        _append_unique(targets, url.rstrip("),;"))

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    previous = ""
    ignored_option_values = {
        "-w", "--wordlist", "-o", "-output", "--output", "-r", "--request",
        "-H", "--header", "-u", "--user", "-p", "--password", "-l", "--login",
        "-P", "-c", "--config", "-b", "--base", "-m", "-M",
    }

    for token in tokens:
        if previous in ignored_option_values:
            previous = token
            continue
        previous = token

        clean = token.strip().strip("'\"(),;")
        if not clean or clean.startswith("-") or clean.startswith(("/", "./", "../")):
            continue
        if "=" in clean:
            clean = clean.rsplit("=", 1)[-1]
        if "://" in clean:
            continue
        if "@" in clean:
            clean = clean.rsplit("@", 1)[-1]
        if ":" in clean and clean.count(":") == 1:
            clean = clean.split(":", 1)[0]

        if _looks_like_network_target(clean):
            _append_unique(targets, clean)

    return targets


def _target_host(target: str) -> str:
    value = target.strip()
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or ""
    # Handle host:port inputs (e.g. 192.168.0.1:443) used by TLS scanners.
    # urlparse with a // prefix correctly strips the port component.
    if ":" in value and not value.startswith("["):
        parsed = urlparse(f"//{value}")
        if parsed.hostname:
            return parsed.hostname
    return value.split("/", 1)[0] if "/" in value and not _is_cidr(value) else value


def _looks_like_network_target(value: str) -> bool:
    if _FILE_EXT_RE.search(value):
        return False
    if _is_cidr(value):
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    return bool(_DOMAIN_RE.match(value) and _HOST_RE.match(value))


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def _append_unique(values: list[str], value: str):
    if value not in values:
        values.append(value)
