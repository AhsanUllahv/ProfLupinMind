# ProfLupinMind

ProfLupinMind is a local MCP-first security automation framework for authorized testing.
It exposes Kali/Linux tooling through an MCP server so clients (Codex, Claude Code, Claude Desktop, and other MCP hosts) can run guarded workflows.

## Architecture

MCP client
  -> `mcp_server.py` (FastMCP, SSE/stdio)
  -> `proflupinmind_api.py` (local Flask execution backend)
  -> local Kali/Linux tools

Key files:
- `main.py` — thin entry alias that runs `mcp_server.main()`
- `mcp_server.py` — MCP server, tool surface, runtime/guardian/session orchestration
- `proflupinmind_api.py` — local command execution backend
- `proflupinmind_client.py` — HTTP client from MCP layer to Flask backend

## Current runtime facts

- MCP SSE endpoint: `http://127.0.0.1:8890/sse`
- Flask health endpoint: `http://127.0.0.1:8887/health`
- Registered MCP tools: `173`
- Startup order:
1. Logo + banner
2. Startup card
3. Flask/API + werkzeug + client connection logs

## Requirements

- Python 3.11+
- Kali/Linux tools installed as needed for your workflows
- Python deps from `requirements.txt`
- Optional: `chafa` for terminal logo rendering
- Optional: Anthropic API key for AI-assisted autonomous analysis features

## Setup

```bash
cd /home/kali/Desktop/kaliwithAI
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional `.env`:

```env
ANTHROPIC_API_KEY=your_key_here
```

## Run

SSE (recommended for VS Code / Claude Code style clients):

```bash
python3 -u mcp_server.py --transport sse --host 127.0.0.1 --port 8890
```

Stdio (for clients that launch MCP servers directly):

```bash
python3 -u mcp_server.py --transport stdio
```

## Logo behavior (updated)

Terminal logo is controlled by `ProfLupinMindVisualEngine.terminal_logo()`.

Environment variables:
- `PROFLUPINMIND_LOGO_MODE=auto|chafa|static|off` (default: `auto`)
- `PROFLUPINMIND_LOGO_PATH` (default: `assets/logo-lines-wr.png`)
- `PROFLUPINMIND_LOGO_WIDTH` (default: `96`)
- `PROFLUPINMIND_LOGO_HEIGHT` (default: `38`)

Current assets expectation:
- Primary logo asset: `assets/logo-lines-wr.png`

## MCP client config examples

SSE:

```json
{
  "mcpServers": {
    "proflupinmind": {
      "type": "sse",
      "url": "http://127.0.0.1:8890/sse"
    }
  }
}
```

Stdio:

```json
{
  "mcpServers": {
    "proflupinmind": {
      "type": "stdio",
      "command": "/home/kali/Desktop/kaliwithAI/.venv/bin/python",
      "args": ["/home/kali/Desktop/kaliwithAI/mcp_server.py", "--transport", "stdio"]
    }
  }
}
```

## Notes

- `proflupinmind_api.py` is started automatically by `mcp_server.py`.
- Keep this deployment local and trusted; do not expose to untrusted networks.
- All usage must be authorized.
