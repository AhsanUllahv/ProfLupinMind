#!/usr/bin/env python3
"""ProfLupinMind entry point.

Runs the FastMCP server. The project is configured for Claude Code in VS Code
through `.mcp.json`, which launches `mcp_server.py --transport stdio`.
"""
from mcp_server import main

if __name__ == "__main__":
    main()
