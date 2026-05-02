# ProfLupinMind Plan (Current Snapshot)

This document reflects the current implemented architecture and operating model.

## Mission

Provide a local MCP-first security automation platform for authorized testing with guarded execution, reproducible workflows, and terminal-visible output.

## Implemented architecture

MCP client
  -> `mcp_server.py` (FastMCP)
  -> `proflupinmind_api.py` (Flask executor)
  -> local Kali/Linux tools

### Module roles

- `main.py`
  - Entry alias that calls `mcp_server.main()`.

- `mcp_server.py`
  - Tool registration and MCP surface.
  - Runtime helpers, safety guardian, task/session/report plumbing.
  - Startup visuals (logo + figlet banner + startup card).
  - Starts backend through `_init_api_backend()` after banner output.

- `proflupinmind_api.py`
  - Local Flask process/thread endpoint for command execution.
  - Streams command output lines to terminal.

- `proflupinmind_client.py`
  - MCP-side HTTP client with health probing and retries.

## Operational facts (verified)

- Tool count: `173`
- Default MCP transport port: `8890`
- Flask backend port: `8887`
- Startup print order:
1. Banner/logo
2. Startup card
3. Flask and client logs

## Branding / terminal logo

`ProfLupinMindVisualEngine.terminal_logo()` modes:
- `auto` (default)
- `chafa`
- `static`
- `off`

Default logo asset path:
- `assets/logo-lines-wr.png`

## Documentation sync goals

- Keep README, setup, and deployment docs aligned with live defaults.
- Keep startup sequencing and logo behavior documented as implemented.
- Keep tool inventory references synced with real registry count.

## Next quality improvements

- Optional terminal capability detection (`kitty`/`sixel`) before symbol fallback.
- Optional `--no-banner` startup flag for minimal logs.
- Add automated doc sanity check for key constants (ports, tool count, defaults).
