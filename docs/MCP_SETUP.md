# ProfLupinMind MCP Setup

Primary setup target: local SSE MCP usage with `mcp_server.py`.

## Components

- `mcp_server.py` — FastMCP server and tool surface
- `proflupinmind_api.py` — Flask backend for command execution
- `proflupinmind_client.py` — API client used by MCP layer
- `main.py` — alias to `mcp_server.main()`

## Current ports

- MCP SSE: `127.0.0.1:8890`
- Flask API: `127.0.0.1:8887`

## Install

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

```bash
python3 -u mcp_server.py --transport sse --port 8890
```

Equivalent alias:

```bash
python3 -u main.py --transport sse --port 8890
```

## Startup output order

1. Custom logo/banner
2. MCP startup card
3. Flask + werkzeug + API client connection lines

This ordering is intentional in current code (`_init_api_backend()` is called in `main()` after banner/card printing).

## Logo controls

- `PROFLUPINMIND_LOGO_MODE=auto|chafa|static|off` (default `auto`)
- `PROFLUPINMIND_LOGO_PATH` default: `assets/logo-lines-wr.png`
- `PROFLUPINMIND_LOGO_WIDTH` default: `96`
- `PROFLUPINMIND_LOGO_HEIGHT` default: `38`

## Client config snippets

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

## Health checks

```bash
curl -s http://127.0.0.1:8890/health
curl -s http://127.0.0.1:8887/health
```

## Tool inventory

```bash
python3 -u -c "from tools.registry import TOOL_REGISTRY; print(len(TOOL_REGISTRY))"
```

Current count: `173`

## Troubleshooting

- If logo doesn’t show: ensure `chafa` is installed or set `PROFLUPINMIND_LOGO_MODE=static`.
- If Flask port busy: free `127.0.0.1:8887` or stop conflicting process.
- If MCP port busy: run another port, e.g. `--port 8891`.
