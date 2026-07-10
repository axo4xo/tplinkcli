"""Command-line interface for the TP-Link router.

Usage examples:
    tplink clients                 # list connected devices
    tplink status                  # router / wan overview
    tplink reboot --yes            # reboot without the confirm prompt
    tplink raw status?form=client_status --op load --json
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

from .client import AuthError, TplinkClient, TplinkError
from .config import Config, ConfigError


def _print_table(rows: list[dict[str, Any]], columns: list[str]) -> None:
    if not rows:
        print("(none)")
        return
    widths = {c: len(c) for c in columns}
    for r in rows:
        for c in columns:
            widths[c] = max(widths[c], len(str(r.get(c, ""))))
    header = "  ".join(c.upper().ljust(widths[c]) for c in columns)
    print(header)
    print("  ".join("-" * widths[c] for c in columns))
    for r in rows:
        print("  ".join(str(r.get(c, "")).ljust(widths[c]) for c in columns))


def _client(args: argparse.Namespace) -> TplinkClient:
    cfg = Config.load(host=args.host, username=args.username, password=args.password)
    client = TplinkClient(cfg.host, cfg.password, cfg.username, secure_hash=cfg.secure_hash)
    client.login()
    return client


# -- commands ---------------------------------------------------------------

def cmd_login(args: argparse.Namespace) -> int:
    client = _client(args)
    if args.json:
        print(json.dumps({"stok": client.stok}))
    else:
        print(f"logged in; stok={client.stok}")
    return 0


def cmd_clients(args: argparse.Namespace) -> int:
    client = _client(args)
    groups = client.get_clients()
    if args.json:
        print(json.dumps(groups, indent=2))
        return 0
    rows = []
    for kind, items in (("wired", groups["wired"]), ("wifi", groups["wireless"]), ("guest", groups["guest"])):
        for it in items:
            rows.append(
                {
                    "type": it.get("wire_type", kind),
                    "hostname": it.get("hostname", ""),
                    "ip": it.get("ipaddr", ""),
                    "mac": it.get("macaddr", ""),
                }
            )
    print(f"{len(rows)} connected device(s):\n")
    _print_table(rows, ["type", "hostname", "ip", "mac"])
    return 0


def _fmt_uptime(seconds: Any) -> str:
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    parts = [f"{d}d" if d else "", f"{h}h" if h else "", f"{m}m", f"{s}s"]
    return " ".join(p for p in parts if p)


def cmd_status(args: argparse.Namespace) -> int:
    client = _client(args)
    mode = client.get_sysmode()
    alld = client.get_status_all()
    if args.json:
        print(json.dumps({"sysmode": mode, "status": alld}, indent=2))
        return 0
    print(f"mode:      {mode.get('mode', '?')}")
    print(f"wan ip:    {alld.get('wan_ipv4_ipaddr', '?')}")
    print(f"uptime:    {_fmt_uptime(alld.get('wan_ipv4_uptime'))}")
    cpu = alld.get("cpu_usage")
    mem = alld.get("mem_usage")
    if cpu is not None:
        print(f"cpu:       {float(cpu) * 100:.0f}%")
    if mem is not None:
        print(f"memory:    {float(mem) * 100:.0f}%")
    ssid_2g = alld.get("wireless_2g_ssid")
    ssid_5g = alld.get("wireless_5g_ssid")
    if ssid_2g:
        print(f"2.4G SSID: {ssid_2g}")
    if ssid_5g:
        print(f"5G SSID:   {ssid_5g}")
    return 0


def cmd_wan(args: argparse.Namespace) -> int:
    client = _client(args)
    print(json.dumps(client.get_wan_status(), indent=2))
    return 0


def cmd_wifi(args: argparse.Namespace) -> int:
    client = _client(args)
    bands = client.get_wifi()
    if args.json:
        print(json.dumps(bands, indent=2))
        return 0
    rows = [
        {
            "band": b["band"],
            "ssid": b["ssid"],
            "password": b["password"] or "",
            "state": "on" if b["enabled"] else "off",
            "security": b["security"] or "",
        }
        for b in bands
    ]
    _print_table(rows, ["band", "ssid", "password", "state", "security"])
    return 0


def cmd_ports(args: argparse.Namespace) -> int:
    client = _client(args)
    ports = client.get_ethernet_ports()
    if args.json:
        print(json.dumps(ports, indent=2))
        return 0
    rows = [
        {
            "port": p.get("name", ""),
            "role": "WAN" if p.get("is_wan") else "LAN",
            "status": p.get("status", ""),
            "speed": p.get("speed", ""),
            "duplex": p.get("duplex", ""),
        }
        for p in ports
    ]
    _print_table(rows, ["port", "role", "status", "speed", "duplex"])
    return 0


def cmd_dhcp(args: argparse.Namespace) -> int:
    client = _client(args)
    leases = client.get_dhcp_leases()
    if args.json:
        print(json.dumps(leases, indent=2))
        return 0
    rows = [
        {
            "hostname": l.get("name", ""),
            "ip": l.get("ipaddr", ""),
            "mac": l.get("macaddr", ""),
            "lease": l.get("leasetime", ""),
        }
        for l in leases
    ]
    print(f"{len(rows)} DHCP lease(s):\n")
    _print_table(rows, ["hostname", "ip", "mac", "lease"])
    return 0


def cmd_reboot(args: argparse.Namespace) -> int:
    if not args.yes:
        reply = input("Reboot the router now? [y/N] ").strip().lower()
        if reply not in {"y", "yes"}:
            print("aborted")
            return 1
    client = _client(args)
    client.reboot()
    print("reboot requested")
    return 0


def cmd_raw(args: argparse.Namespace) -> int:
    params: dict[str, str] = {}
    for kv in args.param or []:
        key, _, val = kv.partition("=")
        params[key] = val
    client = _client(args)
    data = client.request(args.form_path, operation=args.op, params=params or None)
    print(json.dumps(data, indent=2))
    return 0


# -- parser -----------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tplink", description="Control a TP-Link Archer/AX router from the CLI.")
    p.add_argument("--host", help="router IP/host (default: ROUTER_IP from .env)")
    p.add_argument("--username", help="login username (default: admin)")
    p.add_argument("--password", help="login password (default: ROUTER_PASSWORD from .env)")
    sub = p.add_subparsers(dest="command", required=True)

    def add(name: str, fn, help_: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=fn)
        sp.add_argument("--json", action="store_true", help="output raw JSON")
        return sp

    add("login", cmd_login, "log in and print the session token")
    add("clients", cmd_clients, "list connected devices")
    add("status", cmd_status, "router + WAN overview")
    add("wan", cmd_wan, "WAN/internet status (JSON)")
    add("wifi", cmd_wifi, "list SSIDs, passwords and on/off state per band")
    add("ports", cmd_ports, "physical ethernet port link status")
    add("dhcp", cmd_dhcp, "DHCP lease list")
    reboot = add("reboot", cmd_reboot, "reboot the router")
    reboot.add_argument("--yes", action="store_true", help="skip confirmation")
    raw = add("raw", cmd_raw, "call any endpoint: raw <module?form=x>")
    raw.add_argument("form_path", help='e.g. "status?form=client_status"')
    raw.add_argument("--op", default="read", help="operation (read/load/write/...)")
    raw.add_argument("--param", action="append", help="extra body param k=v (repeatable)")
    return p


def _silence_tls_warnings() -> None:
    # The router uses a self-signed cert, so verify_tls is off by default. Silence the
    # per-request InsecureRequestWarning here at the app entry point (not in the library).
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main(argv: Optional[list[str]] = None) -> int:
    _silence_tls_warnings()
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    except AuthError as e:
        print(f"auth error: {e}", file=sys.stderr)
        return 3
    except TplinkError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
