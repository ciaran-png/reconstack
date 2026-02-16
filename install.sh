#!/bin/bash
# ReconStack — install dependencies for all MCP servers
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVERS_DIR="$SCRIPT_DIR/servers"

echo "==================================="
echo "  ReconStack Installer"
echo "==================================="

action_fail() {
  echo "❌ $1"
  exit 1
}

command -v python3 >/dev/null 2>&1 || action_fail "Python 3 is required."
python3 -m pip --version >/dev/null 2>&1 || action_fail "python3 -m pip is required."

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")')
echo "✅ Python $PYTHON_VERSION detected"

echo ""
echo "Installing server dependencies..."
echo ""

INSTALLED=0
FAILED=0

for server_dir in "$SERVERS_DIR"/*/; do
  server_name=$(basename "$server_dir")
  req_file="$server_dir/requirements.txt"
  pyproject_file="$server_dir/pyproject.toml"

  echo "📦 $server_name"

  if [ -f "$req_file" ]; then
    if python3 -m pip install --quiet -r "$req_file"; then
      echo "   ✅ Installed from requirements.txt"
      INSTALLED=$((INSTALLED + 1))
    else
      echo "   ⚠️ Failed requirements install"
      FAILED=$((FAILED + 1))
    fi
  elif [ -f "$pyproject_file" ]; then
    if python3 -m pip install --quiet "$server_dir"; then
      echo "   ✅ Installed from pyproject.toml"
      INSTALLED=$((INSTALLED + 1))
    else
      echo "   ⚠️ Failed pyproject install"
      FAILED=$((FAILED + 1))
    fi
  else
    echo "   ⚠️ No dependency manifest found"
    FAILED=$((FAILED + 1))
  fi
done

echo ""
echo "==================================="
echo "  Installation Complete"
echo "  ✅ Successful: $INSTALLED"
echo "  ⚠️ Failed: $FAILED"
echo "==================================="
echo ""
echo "Next steps:"
echo "  1. cp .env.example .env"
echo "  2. Edit .env with your keys"
echo "  3. ./configure-claude.sh"
