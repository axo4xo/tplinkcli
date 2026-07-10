"""MCP server exposing the router as tools for an AI agent.

Run with:  python -m tplinkcli.mcp_server     (reads .env / env for credentials)
Requires the optional dependency:  pip install "tplinkcli[mcp]"
"""

from __future__ import annotations

from typing import Any, Optional

from .client import AuthError, TplinkClient
from .config import Config

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The MCP SDK is not installed. Install it with: pip install 'tplinkcli[mcp]'"
    ) from exc

mcp = FastMCP("tplink-router")

_client: Optional[TplinkClient] = None


def _get_client() -> TplinkClient:
    global _client
    if _client is None:
        cfg = Config.load()
        _client = TplinkClient(cfg.host, cfg.password, cfg.username, secure_hash=cfg.secure_hash)
        _client.login()
    return _client


def _call(fn):
    """Run a client method, re-logging in once if the session went stale."""
    try:
        return fn(_get_client())
    except AuthError:
        global _client
        _client = None
        return fn(_get_client())


@mcp.tool()
def list_clients() -> dict[str, list[dict[str, Any]]]:
    """List devices currently connected to the router (wired, wireless, guest)."""
    return _call(lambda c: c.get_clients())


@mcp.tool()
def router_status() -> dict[str, Any]:
    """Router overview: operation mode, WAN IP, uptime, CPU/memory usage, SSIDs."""
    return _call(lambda c: {"sysmode": c.get_sysmode(), "status": c.get_status_all()})


@mcp.tool()
def wifi_info() -> list[dict[str, Any]]:
    """SSID, password, security and on/off state for every wireless band."""
    return _call(lambda c: c.get_wifi())


@mcp.tool()
def dhcp_leases() -> list[dict[str, Any]]:
    """Current DHCP leases (hostname, IP, MAC, lease time)."""
    return _call(lambda c: c.get_dhcp_leases())


@mcp.tool()
def ethernet_ports() -> list[dict[str, Any]]:
    """Physical ethernet port link status (WAN/LAN, up/down, speed, duplex)."""
    return _call(lambda c: c.get_ethernet_ports())


@mcp.tool()
def set_wifi_band(band: str, enabled: bool) -> str:
    """Enable or disable a wireless band ('2g', '5g', '5g_2', '6g')."""
    _call(lambda c: c.set_wireless_enabled(band, enabled))
    return f"wireless {band} set to {'on' if enabled else 'off'}"


@mcp.tool()
def raw_request(form_path: str, operation: str = "read", params: Optional[dict[str, Any]] = None) -> Any:
    """Call any router endpoint, e.g. form_path='status?form=client_status', operation='load'.

    This is an escape hatch; available endpoints and operations vary by model/firmware.
    """
    return _call(lambda c: c.request(form_path, operation=operation, params=params))


@mcp.tool()
def reboot_router(confirm: bool = False) -> str:
    """Reboot the router. Must be called with confirm=True to actually reboot."""
    if not confirm:
        return "refused: call again with confirm=True to reboot"
    _call(lambda c: c.reboot())
    return "reboot requested"


def main() -> None:
    # Self-signed router cert: silence the per-request warning at the app entry point.
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    mcp.run()


if __name__ == "__main__":
    main()
