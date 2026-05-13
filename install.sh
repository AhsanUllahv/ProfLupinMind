#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROFLUPINMIND_VENV:-$PROJECT_ROOT/.venv}"
BIN_DIR="${PROFLUPINMIND_BIN_DIR:-$HOME/.local/bin}"
LAUNCHER="$BIN_DIR/proflupinmind-mcp"
REGISTER_CLAUDE_CODE=0

usage() {
  cat <<'EOF'
ProfLupinMind installer

Usage:
  ./install.sh [options]

Options:
  --claude-code       Register ProfLupinMind with Claude Code at user scope.
  --help              Show this help.

Examples:
  ./install.sh
  ./install.sh --claude-code

After --claude-code, ProfLupinMind is available to Claude Code from any folder.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --claude-code)
      REGISTER_CLAUDE_CODE=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    return 1
  fi
}

echo "Installing ProfLupinMind from: $PROJECT_ROOT"
require_command python3

if [[ ! -d "$VENV_DIR" ]]; then
  echo "Creating Python virtual environment: $VENV_DIR"
  python3 -m venv "$VENV_DIR"
fi

PYTHON_BIN="$VENV_DIR/bin/python"
if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "Could not find virtualenv Python at: $PYTHON_BIN" >&2
  exit 1
fi

echo "Installing Python dependencies"
"$PYTHON_BIN" -m pip install --upgrade pip
"$PYTHON_BIN" -m pip install -r "$PROJECT_ROOT/requirements.txt"

mkdir -p "$BIN_DIR"
cat > "$LAUNCHER" <<EOF
#!/usr/bin/env bash
set -Eeuo pipefail
export PROFLUPINMIND_HOME="$PROJECT_ROOT"
cd "$PROJECT_ROOT"
exec "$PYTHON_BIN" "$PROJECT_ROOT/mcp_server.py" "\$@"
EOF
chmod +x "$LAUNCHER"

echo "Created launcher: $LAUNCHER"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo "Note: add this to your shell profile if it is not already there:"
  echo "  export PATH=\"$BIN_DIR:\$PATH\""
fi

if [[ "$REGISTER_CLAUDE_CODE" -eq 1 ]]; then
  require_command claude
  echo "Registering Claude Code MCP server at user scope"
  claude mcp remove -s user proflupinmind >/dev/null 2>&1 || true
  claude mcp add -s user \
    -e PROFLUPINMIND_LOGO_MODE=off \
    -e PROFLUPINMIND_SHOW_STDIO_BANNER=0 \
    -e PROFLUPINMIND_MIRROR_RAW_OUTPUT=1 \
    proflupinmind -- "$LAUNCHER" --transport stdio
  echo "Claude Code registration complete."
fi

echo
echo "Done."
echo "Smoke test:"
echo "  timeout 3 \"$LAUNCHER\" --transport stdio"
if [[ "$REGISTER_CLAUDE_CODE" -eq 1 ]]; then
  echo "Claude Code check:"
  echo "  claude mcp list"
  echo "  claude mcp get proflupinmind"
fi
