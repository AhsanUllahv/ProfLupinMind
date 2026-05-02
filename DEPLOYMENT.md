# ProfLupinMind Deployment

This guide deploys ProfLupinMind as a local MCP server for authorized security testing.

## Topology

MCP client -> `127.0.0.1:8890/sse` -> `mcp_server.py` -> `proflupinmind_api.py` -> local tools

## Prerequisites

- Python 3.11+
- Virtual environment with `requirements.txt` installed
- Local Kali/Linux security tooling
- Optional: `chafa` for logo rendering
- Optional: `ANTHROPIC_API_KEY` for AI-assisted autonomous analysis

## Start server

```bash
source .venv/bin/activate
python3 -u mcp_server.py --transport sse --host 127.0.0.1 --port 8890
```

Endpoints:
- MCP SSE: `http://127.0.0.1:8890/sse`
- MCP health: `http://127.0.0.1:8890/health`
- Flask health: `http://127.0.0.1:8887/health`

## Startup order (current)

1. Logo + banner
2. Startup card
3. Flask/API startup logs and health connect logs

## Client configuration

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

## Logo settings

Supported env vars:
- `PROFLUPINMIND_LOGO_MODE=auto|chafa|static|off`
- `PROFLUPINMIND_LOGO_PATH` (default `assets/logo-lines-wr.png`)
- `PROFLUPINMIND_LOGO_WIDTH` (default `96`)
- `PROFLUPINMIND_LOGO_HEIGHT` (default `38`)

## Verification

```bash
curl -s http://127.0.0.1:8890/health
curl -s http://127.0.0.1:8887/health
python3 -u -c "from tools.registry import TOOL_REGISTRY; print(len(TOOL_REGISTRY))"
```

Expected tool count: `173`

## Security

- Keep service bound to localhost unless you fully trust and isolate network access.
- Do not expose ports `8890` or `8887` publicly.
- Treat scan outputs as sensitive.
- Use only with explicit authorization.
