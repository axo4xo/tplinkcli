# tplinkcli

> next time imma flash my own openwrt so i dont have to do this shit

A CLI + MCP tool for TP-Link Archer/AX routers, so you can manage the router from the terminal instead of the web UI. Reverse-engineered from the site's JS.

## Setup

Uses [uv](https://docs.astral.sh/uv/). 

```sh
uv sync                  # creates .venv, installs deps
uv sync --extra mcp      # the same + the MCP server
```

Create an `.env`:

```sh
ROUTER_IP=192.168.0.1
ROUTER_USERNAME=admin
ROUTER_PASSWORD=your-router-password
```

## CLI

Run via `uv run`:

```sh
uv run tplink clients          # connected devices with IP + MAC
uv run tplink status           # mode, WAN IP, uptime, CPU/mem, SSIDs
uv run tplink wifi             # SSID, password and on/off state per band
uv run tplink ports            # physical ethernet port link status
uv run tplink dhcp             # DHCP leases
uv run tplink wan              # WAN/internet status (JSON)
uv run tplink reboot           # reboot (asks to confirm; --yes to skip)

uv run tplink raw 'status?form=client_status' --op load --json  # call any endpoint directly
```

Quote the `raw` path. Add `--json` to most commands for machine-readable output.

## MCP server

Exposes the router to an AI agent (`list_clients`, `router_status`, `wifi_info`,
`dhcp_leases`, `ethernet_ports`, `set_wifi_band`, `raw_request`, `reboot_router`):

```sh
uv run tplink-mcp      # or: uv run python -m tplinkcli.mcp_server
```

Example Claude Code config:

```json
{
  "mcpServers": {
    "tplink": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/tplinkcli", "tplink-mcp"],
      "env": { "ROUTER_IP": "192.168.0.1", "ROUTER_PASSWORD": "..." }
    }
  }
}
```

## Development

```sh
uv sync --extra mcp    # dev tools (pytest) are in the default dependency group
uv run pytest -q       # crypto tests run offline (synthetic vectors only)
```
