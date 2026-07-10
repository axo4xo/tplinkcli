"""Configuration loading: .env file < environment variables < explicit args.

Only three settings matter: the router host, the username (almost always ``admin``),
and the password. Kept out of the code and git via ``.env`` (see ``.env.example``).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        val = val.strip().strip('"').strip("'")
        values[key.strip()] = val
    return values


def find_env_file(start: Optional[Path] = None) -> Optional[Path]:
    """Walk up from ``start`` (cwd) looking for a .env file."""
    here = (start or Path.cwd()).resolve()
    for directory in (here, *here.parents):
        candidate = directory / ".env"
        if candidate.is_file():
            return candidate
    return None


@dataclass
class Config:
    host: str
    password: str
    username: str = "admin"
    secure_hash: bool = False

    @classmethod
    def load(
        cls,
        *,
        host: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        env_file: Optional[Path] = None,
    ) -> "Config":
        file_vals = _parse_env_file(env_file or find_env_file() or Path(".env"))

        def pick(explicit: Optional[str], *keys: str) -> Optional[str]:
            if explicit:
                return explicit
            for key in keys:
                if os.environ.get(key):
                    return os.environ[key]
            for key in keys:
                if file_vals.get(key):
                    return file_vals[key]
            return None

        resolved_host = pick(host, "ROUTER_IP", "ROUTER_HOST", "TPLINK_HOST")
        resolved_user = pick(username, "ROUTER_USERNAME", "TPLINK_USERNAME") or "admin"
        resolved_pass = pick(password, "ROUTER_PASSWORD", "TPLINK_PASSWORD")
        secure = (pick(None, "ROUTER_SECURE_HASH") or "").lower() in {"1", "true", "yes"}

        missing = [n for n, v in (("host", resolved_host), ("password", resolved_pass)) if not v]
        if missing:
            raise ConfigError(
                f"missing required config: {', '.join(missing)}. "
                f"Set ROUTER_IP and ROUTER_PASSWORD in .env, env vars, or pass flags."
            )
        assert resolved_host and resolved_pass  # for type-checkers
        return cls(host=resolved_host, password=resolved_pass, username=resolved_user, secure_hash=secure)


class ConfigError(Exception):
    pass
