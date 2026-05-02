#!/usr/bin/env python3
"""HTTP client for the ProfLupinMind Flask API server.

Usage in mcp_server.py:
    from proflupinmind_client import ProfLupinMindClient
    _api = ProfLupinMindClient()
    result = _api.execute("nmap -sV 192.168.0.1")
    result = _api.tool("nmap", target="192.168.0.1", scan_type="-sV")
"""
import logging
import os
import time
import requests

logger = logging.getLogger(__name__)

DEFAULT_HOST = os.environ.get("PROFLUPINMIND_API_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("PROFLUPINMIND_API_PORT", 8887))
DEFAULT_URL = f"http://{DEFAULT_HOST}:{DEFAULT_PORT}"
MAX_RETRIES = 3


class ProfLupinMindClient:
    """Communicates with the ProfLupinMind Flask API server (hexstrike-style proxy)."""

    def __init__(self, server_url: str = DEFAULT_URL, timeout: int = 300):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.available = self._connect()

    def _connect(self) -> bool:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                r = self.session.get(f"{self.server_url}/health", timeout=5)
                r.raise_for_status()
                data = r.json()
                logger.info(
                    f"✅ ProfLupinMind API connected | status={data.get('status')} "
                    f"| v{data.get('version')} | uptime={data.get('uptime')}s"
                )
                return True
            except Exception as exc:
                logger.warning(
                    f"⚠️  ProfLupinMind API connection attempt {attempt}/{MAX_RETRIES}: {exc}"
                )
                if attempt < MAX_RETRIES:
                    time.sleep(1.5)
        logger.error(f"❌ ProfLupinMind API not reachable at {self.server_url}")
        return False

    def health(self) -> dict:
        try:
            r = self.session.get(f"{self.server_url}/health", timeout=5)
            return r.json()
        except Exception as exc:
            return {"error": str(exc)}

    def execute(self, command: str, timeout: int = 300) -> dict:
        """Run an arbitrary shell command via the API."""
        try:
            r = self.session.post(
                f"{self.server_url}/api/command",
                json={"command": command, "timeout": timeout},
                timeout=timeout + 15,
            )
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            logger.error(f"❌ API execute failed: {exc}")
            return {"success": False, "error": str(exc), "output": "", "exit_code": -1,
                    "duration": 0.0, "timed_out": False, "command": command}

    def tool(self, tool_name: str, timeout: int = 300, **params) -> dict:
        """Call a named tool endpoint on the API."""
        params["timeout"] = timeout
        try:
            r = self.session.post(
                f"{self.server_url}/api/tools/{tool_name}",
                json=params,
                timeout=timeout + 15,
            )
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            logger.error(f"❌ API tool '{tool_name}' failed: {exc}")
            return {"success": False, "error": str(exc), "output": "", "exit_code": -1,
                    "duration": 0.0, "timed_out": False}
