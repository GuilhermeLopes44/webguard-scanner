from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.auth import TargetAuth

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = ROOT_DIR / "webguard.yaml"
DATA_DIR = ROOT_DIR / "data"

DEFAULT_CHECKS = [
    "security_headers",
    "cookie_flags",
    "tech_detect",
    "xss_reflected",
    "sqli_error",
    "open_redirect",
    "cors_misconfig",
    "sensitive_paths",
    "csrf_heuristic",
]


@dataclass
class AppConfig:
    max_pages: int = 5
    max_depth: int = 2
    timeout: float = 5.0
    rate_limit_rps: float = 8.0
    max_fuzz_params: int = 8
    max_fuzz_forms: int = 4
    max_payloads: int = 2
    user_agent: str = "WebGuard/1.0 (+local authorized scanner)"
    allowlist_hosts: list[str] = field(default_factory=list)
    enabled_checks: list[str] = field(default_factory=lambda: list(DEFAULT_CHECKS))
    server_host: str = "127.0.0.1"
    server_port: int = 5000
    server_debug: bool = False
    target_auth: TargetAuth = field(default_factory=TargetAuth)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AppConfig":
        checks = data.get("checks") or {}
        enabled = checks.get("enabled") or list(DEFAULT_CHECKS)
        server = data.get("server") or {}
        return cls(
            max_pages=int(data.get("max_pages", 5)),
            max_depth=int(data.get("max_depth", 2)),
            timeout=float(data.get("timeout", 5)),
            rate_limit_rps=float(data.get("rate_limit_rps", 8.0)),
            max_fuzz_params=int(data.get("max_fuzz_params", 8)),
            max_fuzz_forms=int(data.get("max_fuzz_forms", 4)),
            max_payloads=int(data.get("max_payloads", 2)),
            user_agent=str(data.get("user_agent", "WebGuard/1.0 (+local authorized scanner)")),
            allowlist_hosts=list(data.get("allowlist_hosts") or []),
            enabled_checks=list(enabled),
            server_host=str(server.get("host", "127.0.0.1")),
            server_port=int(server.get("port", 5000)),
            server_debug=bool(server.get("debug", False)),
            target_auth=TargetAuth.from_dict(data.get("auth")),
        )


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config must be a mapping: {path}")
    return data


def load_config(path: str | Path | None = None) -> AppConfig:
    """Load config from YAML, then apply env overrides."""
    candidates: list[Path] = []
    if path:
        candidates.append(Path(path))
    env_path = os.environ.get("WEBGUARD_CONFIG")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path.home() / ".webguard" / "config.yaml")
    candidates.append(DEFAULT_CONFIG_PATH)

    data: dict[str, Any] = {}
    for candidate in candidates:
        if candidate.exists():
            data = _load_yaml(candidate)
            break

    cfg = AppConfig.from_dict(data)

    if os.environ.get("WEBGUARD_MAX_PAGES"):
        cfg.max_pages = int(os.environ["WEBGUARD_MAX_PAGES"])
    if os.environ.get("WEBGUARD_TIMEOUT"):
        cfg.timeout = float(os.environ["WEBGUARD_TIMEOUT"])
    if os.environ.get("WEBGUARD_DEBUG", "").lower() in {"1", "true", "yes"}:
        cfg.server_debug = True
    if os.environ.get("WEBGUARD_HOST"):
        cfg.server_host = os.environ["WEBGUARD_HOST"]
    if os.environ.get("WEBGUARD_PORT"):
        cfg.server_port = int(os.environ["WEBGUARD_PORT"])

    return cfg


def get_auth_token() -> str | None:
    token = os.environ.get("WEBGUARD_TOKEN", "").strip()
    return token or None


def load_data_lines(filename: str) -> list[str]:
    path = DATA_DIR / filename
    if not path.exists():
        return []
    lines: list[str] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            lines.append(text)
    return lines
