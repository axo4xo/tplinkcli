# tplinkcli

> next time imma flash my own openwrt so i dont have to do this shit

A CLI + MCP tool for TP-Link Archer/AX routers, so you can manage the router from the terminal instead of the web UI. Reverse-engineered from the site's JS.

## Install

With [uv](https://docs.astral.sh/uv/), install it as a global tool - puts `tplink` and
`tplink-mcp` on your PATH:

```sh
uv tool install '.[mcp]'          # from a local checkout
# uv tool install 'tplinkcli[mcp]'  # once published to PyPI
```

Then put your credentials in `~/.config/tplink/.env`:

```sh
ROUTER_IP=192.168.0.1
ROUTER_USERNAME=admin
ROUTER_PASSWORD=your-router-password
```

Credentials are also read from environment variables, a project-local `.env`, or a file
pointed to by `$TPLINK_ENV` (precedence, low → high: user config → project `.env` →
`$TPLINK_ENV` → env vars → `--host/--password` flags).

## CLI

```sh
tplink clients          # connected devices with IP + MAC
tplink status           # mode, WAN IP, uptime, CPU/mem, SSIDs
tplink wifi             # SSID, password and on/off state per band
tplink ports            # physical ethernet port link status
tplink dhcp             # DHCP leases
tplink wan              # WAN/internet status (JSON)
tplink reboot           # reboot (asks to confirm; --yes to skip)

tplink raw 'status?form=client_status' --op load --json  # call any endpoint directly
```

Quote the `raw` path (the `?` is a shell glob). Add `--json` to most commands for
machine-readable output.

## MCP server

Exposes the router to an AI agent (`list_clients`, `router_status`, `wifi_info`,
`dhcp_leases`, `ethernet_ports`, `set_wifi_band`, `raw_request`, `reboot_router`):

```sh
tplink-mcp
```

Example Claude Code config (credentials via `~/.config/tplink/.env` or inline `env`):

```json
{
  "mcpServers": {
    "tplink": {
      "command": "tplink-mcp",
      "env": { "ROUTER_IP": "192.168.0.1", "ROUTER_PASSWORD": "..." }
    }
  }
}
```

## Development

Work on the code from a checkout without installing globally:

```sh
uv sync --extra mcp    # dev tools (pytest) are in the default dependency group
uv run pytest -q       # crypto tests run offline (synthetic vectors only)
uv run tplink status   # run against the router without a global install

uv tool install --force '.[mcp]'   # reinstall the global tool after changes
```
