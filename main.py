#!/usr/bin/env python3
"""ProfLupinMind entry point.

Starts the Flask API server in a background thread (port 8887) and then
runs the FastMCP server (port 8890 / SSE).  The Flask API handles all
subprocess execution so live tool output is always visible in the terminal.
"""
from mcp_server import main

if __name__ == "__main__":
    main()
