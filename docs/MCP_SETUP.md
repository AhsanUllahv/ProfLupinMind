# ProfLupinMind MCP Setup for Claude Code in VS Code

This project is configured for one MCP client: Claude Code running in VS Code.

## Architecture

```text
Claude Code in VS Code
        |
        v
.mcp.json project config
        |
        v
mcp_server.py --transport stdio
        |
        v
registered tools + workflows + safety checks
        |
        v
local Kali/Linux commands
        |
        v
sessions, findings, reports
```

## Install

```bash
cd /home/kali/Desktop/kaliwithAI
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Claude Code Configuration

Claude Code reads the project-scoped MCP configuration from:

```text
/home/kali/Desktop/kaliwithAI/.mcp.json
```

The server is launched directly by Claude Code using stdio:

```json
{
  "mcpServers": {
    "proflupinmind": {
      "type": "stdio",
      "command": "/home/kali/Desktop/kaliwithAI/.venv/bin/python",
      "args": [
        "/home/kali/Desktop/kaliwithAI/mcp_server.py",
        "--transport",
        "stdio"
      ],
      "env": {
        "PROFLUPINMIND_LOGO_MODE": "auto",
        "PROFLUPINMIND_SHOW_STDIO_BANNER": "1",
        "PROFLUPINMIND_MIRROR_RAW_OUTPUT": "1",
        "PROFLUPINMIND_RAW_OUTPUT_LOG": "/home/kali/Desktop/kaliwithAI/proflupinmind.raw.log",
        "PROFLUPINMIND_EVENTS_LOG": "/home/kali/Desktop/kaliwithAI/proflupinmind.events.jsonl"
      }
    }
  }
}
```

`PROFLUPINMIND_SHOW_STDIO_BANNER=1` shows the startup card without touching stdout, which is reserved for the MCP JSON channel. The banner is written to the controlling terminal when available and mirrored to the raw log.

## Watch Raw Tool Output

Claude Code starts MCP servers as background stdio processes, so there may not be a separate MCP server terminal window. This project mirrors the live terminal stream to:

```text
/home/kali/Desktop/kaliwithAI/proflupinmind.raw.log
```

Open a VS Code terminal and run:

```bash
tail -f /home/kali/Desktop/kaliwithAI/proflupinmind.raw.log
```

When Claude Code starts the ProfLupinMind MCP server, the logo/startup card appears there. When Claude Code runs a ProfLupinMind MCP tool, the raw command output appears there live.

For the old visual terminal feel with the logo and startup card, run:

```bash
cd /home/kali/Desktop/kaliwithAI
.venv/bin/python proflupinmind_console.py
```

This is only a viewer. Claude Code still starts and controls the real MCP server.

Logo modes:

```text
auto   = use chafa image rendering when available
chafa  = require chafa image rendering
off    = hide the logo
```

## Use in VS Code

1. Open this folder in VS Code.
2. Start Claude Code from the project folder.
3. Approve the project MCP server when Claude Code asks about `.mcp.json`.
4. In Claude Code, run:

```text
/mcp
```

You should see `proflupinmind` connected.

Useful CLI checks:

```bash
claude mcp list
claude mcp get proflupinmind
```

## Manual Smoke Test

Run this if you want to verify the server can start in Claude Code mode:

```bash
timeout 3 .venv/bin/python mcp_server.py --transport stdio
```

When run outside an MCP client, stdio mode may exit immediately because stdin is closed. That is fine. It should not show a Python traceback.

## Notes

- Do not run a separate SSE server for Claude Code. Claude Code starts this server through `.mcp.json`.
- Keep usage local and authorized.
- Reports are generated from saved sessions under `reports/output`.
