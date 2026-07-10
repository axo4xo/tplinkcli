"""HTTP client for the TP-Link Archer/AX web API.

Implements the real login handshake (reverse-engineered from the router's web UI JS)
and the encrypted request/response envelope, then exposes typed helpers for
the useful features. Everything runs over the router's self-signed HTTPS.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Optional
from urllib.parse import urlencode

import requests
import urllib3

from .crypto import AesCipher, RsaCipher, TpEncryptor

# NOTE: Do not disable InsecureRequestWarning globally; callers may opt-in if desired.


class TplinkError(Exception):
    """A router call returned ``success: false`` or an unexpected response."""

    def __init__(self, message: str, errorcode: Optional[str] = None) -> None:
        super().__init__(message)
        self.errorcode = errorcode


class AuthError(TplinkError):
    """Login failed or the session is not (or no longer) valid."""


class TplinkClient:
    def __init__(
        self,
        host: str,
        password: str,
        username: str = "admin",
        *,
        timeout: float = 10.0,
        verify_tls: bool = False,
        secure_hash: bool = False,
    ) -> None:
        self.host = host
        self.username = username
        self._password = password
        self.timeout = timeout
        self.verify_tls = verify_tls
        # Firmware with IS_RG_SEC uses SHA256(user+pass); Archer/AX uses MD5.
        self.secure_hash = secure_hash
        self.stok: str = ""
        self.encryptor: Optional[TpEncryptor] = None
        # The router has ONE session; serialize login()/request() so concurrent callers
        # (e.g. the MCP server fielding a batch of tool calls) can't corrupt it.
        self._lock = threading.RLock()
        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-Requested-With": "XMLHttpRequest",
                "Referer": f"https://{host}/webpages/index.html",
                "Accept": "application/json, text/javascript, */*; q=0.01",
            }
        )

    # -- URL / transport ----------------------------------------------------

    def _url(self, path: str) -> str:
        # path starts with "/", e.g. "/login?form=auth" or "/admin/status?form=x"
        return f"https://{self.host}/cgi-bin/luci/;stok={self.stok}{path}"

    def _post(self, path: str, body: dict[str, str]) -> requests.Response:
        return self.session.post(
            self._url(path),
            data=body,
            timeout=self.timeout,
            verify=self.verify_tls,
        )

    def _post_plain(self, path: str, data: dict[str, str]) -> dict[str, Any]:
        """Unencrypted call (login handshake endpoints in the router's no-encrypt list)."""
        r = self._post(path, data)
        r.raise_for_status()
        payload = r.json()
        if not payload.get("success", False):
            raise AuthError(f"{path} failed: {payload}", str(payload.get("errorcode")))
        return payload.get("data", {})

    def _decode(self, payload: dict[str, Any]) -> dict[str, Any]:
        """A response is either plain JSON or {"data": "<base64>"} that we AES-decrypt.

        A dead session (expired, or taken over by the WebUI/another client — the router
        allows one admin at a time) answers with an empty ``data`` string. Surface that as
        an AuthError so callers can re-login, instead of crashing in the AES un-pad.
        """
        data = payload.get("data")
        if isinstance(data, str) and self.encryptor is not None:
            if data == "":
                raise AuthError("empty response — session expired or taken over by another admin")
            return json.loads(self.encryptor.decrypt_response(data))
        return payload

    # -- login --------------------------------------------------------------

    def login(self, force: bool = True) -> str:
        """Perform the full handshake and store the session token. Returns the stok.

        ``force`` retries with ``confirm=true`` if the router reports another active admin
        session (it allows only one), taking over that session — same as the web UI does.
        Serialized with the per-client lock.
        """
        with self._lock:
            return self._login(force)

    def _login(self, force: bool) -> str:
        # 1. RSA key that encrypts the password.
        keys = self._post_plain("/login?form=keys", {"operation": "read"})
        pw_n, pw_e = keys["password"]
        password_rsa = RsaCipher(pw_n, pw_e)

        # 2. RSA signing key + base sequence.
        auth = self._post_plain("/login?form=auth", {"operation": "read"})
        sign_n, sign_e = auth["key"]
        seq = int(auth["seq"])

        # 3. Fresh AES key/iv + login hash, assembled into the session encryptor.
        aes = AesCipher.generate()
        pw_hash = TpEncryptor.compute_hash(self.username, self._password, self.secure_hash)
        self.encryptor = TpEncryptor(aes, RsaCipher(sign_n, sign_e), pw_hash, seq)
        enc_password = password_rsa.encrypt(self._password)

        # 4. Submit the encrypted login (isLogin=True → sign embeds the AES key/iv).
        stok, decoded = self._submit_login(enc_password, confirm=False)
        if not stok and force and _is_conflict(decoded):
            stok, decoded = self._submit_login(enc_password, confirm=True)
        if not stok:
            raise AuthError(f"login failed: {decoded}", str(decoded.get("errorcode")))
        self.stok = stok
        return stok

    def _submit_login(self, enc_password: str, confirm: bool) -> tuple[str, dict[str, Any]]:
        body: dict[str, str] = {"operation": "login"}
        if confirm:
            body["confirm"] = "true"
        body["password"] = enc_password
        assert self.encryptor is not None
        req = self.encryptor.encrypt_request(urlencode(body), is_login=True)
        r = self._post("/login?form=login", req.as_form())
        r.raise_for_status()
        decoded = self._decode(r.json())
        return _find_stok(decoded), decoded

    # -- generic request ----------------------------------------------------

    def request(
        self,
        form_path: str,
        operation: str = "read",
        params: Optional[dict[str, Any]] = None,
    ) -> Any:
        """POST to /admin/<form_path> (e.g. "status?form=client_status") and return data.

        The plaintext body is a url-encoded form string beginning with ``operation=...``.
        Serialized with the per-client lock so concurrent callers (e.g. the MCP server
        handling a batch of tool calls) never race on the single session.
        """
        with self._lock:
            return self._request(form_path, operation, params)

    def _request(
        self,
        form_path: str,
        operation: str = "read",
        params: Optional[dict[str, Any]] = None,
    ) -> Any:
        if self.encryptor is None or not self.stok:
            raise AuthError("not logged in; call login() first")
        body = {"operation": operation}
        if params:
            body.update(params)
        req = self.encryptor.encrypt_request(urlencode(body), is_login=False)
        r = self._post(f"/admin/{form_path}", req.as_form())
        try:
            r.raise_for_status()
        except requests.HTTPError as e:
            raise TplinkError(f"{form_path}: HTTP {r.status_code}: {r.text[:120]!r}") from e
        if not r.text.strip():
            raise AuthError(f"{form_path}: empty response body (HTTP {r.status_code}) — session likely invalid")
        try:
            payload = r.json()
        except ValueError:
            raise TplinkError(f"{form_path}: non-JSON response (HTTP {r.status_code}): {r.text[:120]!r}")
        decoded = self._decode(payload)
        if not decoded.get("success", True):
            code = str(decoded.get("errorcode"))
            if code in {"-40401", "0", "timeout"} or "login" in code.lower():
                raise AuthError(f"session invalid ({code})", code)
            raise TplinkError(f"{form_path} failed: {decoded}", code)
        return decoded.get("data", decoded)

    # -- typed helpers (confirmed against the live device) ------------------

    def get_clients(self) -> dict[str, list[dict[str, Any]]]:
        """Connected devices split into wired / wireless host / wireless guest."""
        data = self.request("status?form=client_status", operation="load")
        return {
            "wired": data.get("access_devices_wired", []),
            "wireless": data.get("access_devices_wireless_host", []),
            "guest": data.get("access_devices_wireless_guest", []),
        }

    def get_wan_status(self) -> dict[str, Any]:
        return self.request("network?form=wan_ipv4_status")

    def get_sysmode(self) -> dict[str, Any]:
        return self.request("system?form=sysmode")

    def get_status_all(self) -> dict[str, Any]:
        """Big status blob: CPU/mem usage, uptime, WAN IP, per-band SSIDs, etc."""
        return self.request("status?form=all")

    def get_ethernet_ports(self) -> list[dict[str, Any]]:
        """Physical port list: name, WAN/LAN, link status, speed, duplex."""
        data = self.request("status?form=router")
        return data if isinstance(data, list) else data.get("ports", [])

    WIFI_BANDS = ("2g", "5g", "5g_2", "6g")

    def get_wireless(self, band: str) -> dict[str, Any]:
        """Host wireless settings for a band (ssid, psk_key, disabled, channel, ...)."""
        return self.request(f"wireless?form=wireless_{band}")

    def get_wifi(self) -> list[dict[str, Any]]:
        """SSID, password and on/off state for every wireless band the router has."""
        out: list[dict[str, Any]] = []
        for band in self.WIFI_BANDS:
            try:
                w = self.get_wireless(band)
            except TplinkError:
                continue
            if not w or not w.get("ssid"):
                continue
            out.append(
                {
                    "band": band,
                    "ssid": w.get("ssid"),
                    "password": w.get("psk_key") or w.get("key"),
                    "security": w.get("encryption"),
                    "enabled": w.get("disabled") not in ("on", True),
                    "hidden": w.get("hidden") == "on",
                    "channel": w.get("current_channel") or w.get("channel"),
                }
            )
        return out

    def get_dhcp_leases(self) -> list[dict[str, Any]]:
        data = self.request("dhcps?form=client", operation="load")
        return data if isinstance(data, list) else data.get("clients", [])

    def reboot(self) -> Any:
        """Reboot the router (operation write)."""
        return self.request("system?form=reboot", operation="write")

    def logout(self) -> None:
        """Release the admin session so another client (e.g. the WebUI) can log in.

        Best-effort: if the session is already gone, there is nothing to release.
        """
        with self._lock:
            if self.logged_in:
                try:
                    self.request("system?form=logout", operation="write")
                except Exception:
                    pass  # session may already be gone / router rebooting
            self.stok = ""
            self.encryptor = None

    @property
    def logged_in(self) -> bool:
        return bool(self.stok and self.encryptor is not None)

    def set_wireless_enabled(self, band: str, enabled: bool) -> Any:
        """Turn a wireless band's host network on or off (operation write)."""
        return self.request(
            f"wireless?form=wireless_{band}",
            operation="write",
            params={"disabled": "off" if enabled else "on"},
        )

    def close(self) -> None:
        self.session.close()

    def __enter__(self) -> "TplinkClient":
        self.login()
        return self

    def __exit__(self, *exc: object) -> None:
        self.logout()
        self.close()


def _find_stok(decoded: dict[str, Any]) -> str:
    if "stok" in decoded:
        return str(decoded["stok"])
    data = decoded.get("data")
    if isinstance(data, dict) and "stok" in data:
        return str(data["stok"])
    return ""


def _is_conflict(decoded: dict[str, Any]) -> bool:
    """Whether a failed login was due to another active admin session (retry with confirm)."""
    blob = json.dumps(decoded).lower()
    return "conflict" in blob or "logined_user" in blob or "login_status" in blob
