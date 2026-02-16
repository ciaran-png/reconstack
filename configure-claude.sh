#!/bin/bash
# ReconStack — configure all servers for Claude Desktop
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVERS_DIR="$SCRIPT_DIR/servers"

if [ -f "$SCRIPT_DIR/.env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$SCRIPT_DIR/.env"
  set +a
  echo "✅ Loaded environment values from .env"
else
  echo "⚠️  No .env file found. Placeholder values will be written for missing keys."
fi

if [ "$(uname)" = "Darwin" ]; then
  CONFIG_DIR="$HOME/Library/Application Support/Claude"
elif [ "$(uname)" = "Linux" ]; then
  CONFIG_DIR="$HOME/.config/claude"
else
  CONFIG_DIR="$HOME/.claude"
fi

CONFIG_FILE="$CONFIG_DIR/claude_desktop_config.json"

echo "Claude Desktop config: $CONFIG_FILE"

env RECONSTACK_SERVERS_DIR="$SERVERS_DIR" RECONSTACK_CONFIG_FILE="$CONFIG_FILE" python3 <<'PY'
import json
import os
from pathlib import Path

servers_dir = Path(os.environ["RECONSTACK_SERVERS_DIR"]).resolve()
config_file = Path(os.environ["RECONSTACK_CONFIG_FILE"]).resolve()

server_specs = [
    {"name": "reconstack-crtsh", "command": "python3", "args": ["crtsh-mcp/server.py"], "env": []},
    {"name": "reconstack-dorker", "command": "python3", "args": ["dorking/server.py"], "env": [
        {"name": "GOOGLE_API_KEY", "aliases": [], "required": True, "emit_aliases": False},
        {"name": "GOOGLE_CSE_ID", "aliases": ["GOOGLE_CX"], "required": True, "emit_aliases": True},
        {"name": "BING_API_KEY", "aliases": [], "required": False, "emit_aliases": False},
        {"name": "SERPAPI_KEY", "aliases": [], "required": False, "emit_aliases": False},
        {"name": "BRAVE_API_KEY", "aliases": [], "required": False, "emit_aliases": False},
    ]},
    {"name": "reconstack-exiftool", "command": "python3", "args": ["exiftool-mcp/server.py"], "env": []},
    {"name": "reconstack-google-dorker", "command": "python3", "args": ["google-dorker/server.py"], "env": [
        {"name": "GOOGLE_API_KEY", "aliases": [], "required": True, "emit_aliases": False},
        {"name": "GOOGLE_CSE_ID", "aliases": ["GOOGLE_CX"], "required": True, "emit_aliases": True},
    ]},
    {"name": "reconstack-holehe", "command": "python3", "args": ["holehe-mcp/server.py"], "env": []},
    {"name": "reconstack-social-analyzer", "command": "python3", "args": ["social-analyzer-mcp/server.py"], "env": []},
    {"name": "reconstack-trufflehog", "command": "python3", "args": ["trufflehog-mcp/server.py"], "env": []},
    {"name": "reconstack-wayback", "command": "python3", "args": ["wayback-mcp/server.py"], "env": []},

    {"name": "reconstack-corpdata", "command": "python3", "args": ["corpdata-mcp/server.py"], "env": [
        {"name": "COMPANIES_HOUSE_API_KEY", "aliases": [], "required": False, "emit_aliases": False},
    ]},
    {"name": "reconstack-dehashed", "command": "python3", "args": ["dehashed-mcp/server.py"], "env": [
        {"name": "DEHASHED_API_KEY", "aliases": [], "required": True, "emit_aliases": False},
        {"name": "DEHASHED_EMAIL", "aliases": [], "required": False, "emit_aliases": False},
    ]},
    {"name": "reconstack-dnslytics", "command": "python3", "args": ["dnslytics-mcp/dnslytics_mcp.py"], "env": []},
    {"name": "reconstack-gitdorker", "command": "python3", "args": ["gitdorker-mcp/server.py"], "env": [
        {"name": "GITHUB_TOKEN", "aliases": [], "required": False, "emit_aliases": False},
    ]},
    {
        "name": "reconstack-neo4j-osint",
        "command": "python3",
        "args": ["-m", "src.server"],
        "cwd": str((servers_dir / "neo4j-osint").resolve()),
        "env": [
            {"name": "NEO4J_URI", "aliases": [], "required": False, "emit_aliases": False},
            {"name": "NEO4J_USER", "aliases": [], "required": False, "emit_aliases": False},
            {"name": "NEO4J_PASSWORD", "aliases": [], "required": False, "emit_aliases": False},
            {"name": "SQLITE_DB_PATH", "aliases": [], "required": False, "emit_aliases": False},
        ],
    },
    {"name": "reconstack-nmap", "command": "python3", "args": ["nmap-mcp/nmap_mcp/server.py"], "env": []},
    {"name": "reconstack-opencorporates", "command": "python3", "args": ["opencorporates-mcp/server.py"], "env": [
        {"name": "OPENCORPORATES_API_KEY", "aliases": [], "required": False, "emit_aliases": False},
    ]},
    {"name": "reconstack-phoneinfoga", "command": "python3", "args": ["phoneinfoga-mcp/server.py"], "env": []},
    {"name": "reconstack-sherlockeye", "command": "python3", "args": ["sherlockeye-mcp/server.py"], "env": [
        {"name": "SHERLOCKEYE_API_KEY", "aliases": [], "required": True, "emit_aliases": False},
    ]},
    {"name": "reconstack-shodan", "command": "python3", "args": ["shodan-mcp/server.py"], "env": [
        {"name": "SHODAN_API_KEY", "aliases": [], "required": True, "emit_aliases": False},
    ]},
    {"name": "reconstack-telegram", "command": "python3", "args": ["telegram-mcp/server.py"], "env": [
        {"name": "TELEGRAM_API_ID", "aliases": ["TG_API_ID"], "required": True, "emit_aliases": True},
        {"name": "TELEGRAM_API_HASH", "aliases": ["TG_API_HASH"], "required": True, "emit_aliases": True},
    ]},
    {"name": "reconstack-urban-scout", "command": "python3", "args": ["urban-scout-mcp/urban_scout.py"], "env": [
        {"name": "GOOGLE_MAPS_API_KEY", "aliases": ["URBAN_SCOUT_API_KEY"], "required": True, "emit_aliases": True},
    ]},
    {"name": "reconstack-virustotal", "command": "python3", "args": ["virustotal-mcp/server.py"], "env": [
        {"name": "VIRUSTOTAL_API_KEY", "aliases": ["VT_API_KEY"], "required": True, "emit_aliases": True},
    ]},
]

if config_file.exists():
    with config_file.open() as fh:
        config = json.load(fh)
else:
    config = {}

config.setdefault("mcpServers", {})


def resolve_env_value(name: str, aliases: list[str]) -> str:
    for key in [name, *aliases]:
        val = os.environ.get(key, "").strip()
        if val:
            return val
    return ""


for spec in server_specs:
    args = spec["args"]
    resolved_args = []
    for arg in args:
        if arg.startswith("-"):
            resolved_args.append(arg)
        elif "/" in arg:
            resolved_args.append(str((servers_dir / arg).resolve()))
        else:
            resolved_args.append(arg)

    entry = {
        "command": spec["command"],
        "args": resolved_args,
    }

    if spec.get("cwd"):
        entry["cwd"] = spec["cwd"]

    env_block = {}
    for env_spec in spec.get("env", []):
        canonical = env_spec["name"]
        aliases = env_spec.get("aliases", [])
        required = env_spec.get("required", False)
        emit_aliases = env_spec.get("emit_aliases", False)

        value = resolve_env_value(canonical, aliases)
        if not value and required:
            value = f"YOUR_{canonical}_HERE"

        if value:
            env_block[canonical] = value
            if emit_aliases:
                for alias in aliases:
                    env_block[alias] = value

    if env_block:
        entry["env"] = env_block

    config["mcpServers"][spec["name"]] = entry

config_file.parent.mkdir(parents=True, exist_ok=True)
with config_file.open("w") as fh:
    json.dump(config, fh, indent=2)

print(f"✅ Added/updated {len(server_specs)} ReconStack servers")
print(f"✅ Wrote: {config_file}")
PY

echo "Done. Restart Claude Desktop to apply changes."
