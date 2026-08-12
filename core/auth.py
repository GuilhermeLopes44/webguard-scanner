from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

from core.logging_setup import get_logger

if TYPE_CHECKING:
    from core.http_client import RateLimitedSession

log = get_logger(__name__)


@dataclass
class TargetAuth:
    """Credentials / session material for authenticated scanning of an authorized target."""

    login_url: str | None = None
    username: str | None = None
    password: str | None = None
    username_field: str = "username"
    password_field: str = "password"
    extra_fields: dict[str, str] = field(default_factory=dict)
    cookie: str | None = None
    authorization: str | None = None
    success_marker: str | None = None
    seed_paths: list[str] = field(default_factory=list)

    def enabled(self) -> bool:
        return bool(
            self.cookie
            or self.authorization
            or (self.login_url and self.username is not None and self.password is not None)
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "TargetAuth":
        data = data or {}
        return cls(
            login_url=data.get("login_url"),
            username=data.get("username"),
            password=data.get("password"),
            username_field=str(data.get("username_field") or "username"),
            password_field=str(data.get("password_field") or "password"),
            extra_fields=dict(data.get("extra_fields") or {}),
            cookie=data.get("cookie"),
            authorization=data.get("authorization"),
            success_marker=data.get("success_marker"),
            seed_paths=list(data.get("seed_paths") or []),
        )


@dataclass
class AuthResult:
    ok: bool
    method: str
    message: str
    seed_urls: list[str] = field(default_factory=list)


def apply_target_auth(
    session: "RateLimitedSession",
    target_url: str,
    auth: TargetAuth,
) -> AuthResult:
    """Establish authenticated session against the target. Same-origin only."""
    if not auth.enabled():
        return AuthResult(ok=True, method="none", message="No target auth configured")

    base = target_url
    seeds: list[str] = []
    for path in auth.seed_paths:
        seeds.append(urljoin(base if base.endswith("/") else base + "/", path.lstrip("/")))

    if auth.authorization:
        session.session.headers["Authorization"] = auth.authorization
        log.info("Applied Authorization header for authenticated scan")
        return AuthResult(
            ok=True,
            method="authorization_header",
            message="Authorization header applied",
            seed_urls=seeds,
        )

    if auth.cookie:
        session.session.headers["Cookie"] = auth.cookie
        host = urlparse(target_url).hostname or ""
        for part in auth.cookie.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            session.session.cookies.set(name.strip(), value.strip(), domain=host)
        log.info("Applied Cookie header for authenticated scan")
        return AuthResult(
            ok=True,
            method="cookie",
            message="Cookie session applied",
            seed_urls=seeds,
        )

    assert auth.login_url and auth.username is not None and auth.password is not None
    login_url = auth.login_url
    if not urlparse(login_url).scheme:
        login_url = urljoin(
            target_url if target_url.endswith("/") else target_url + "/",
            login_url.lstrip("/"),
        )

    form = {
        auth.username_field: auth.username,
        auth.password_field: auth.password,
        **auth.extra_fields,
    }
    log.info("Attempting form login at %s", login_url)
    response = session.post(login_url, data=form)
    if response is None:
        return AuthResult(ok=False, method="form_login", message=f"Login request failed: {login_url}")

    if auth.success_marker and auth.success_marker not in (response.text or ""):
        return AuthResult(
            ok=False,
            method="form_login",
            message=f"Login response missing success marker ({auth.success_marker!r})",
        )

    if not session.session.cookies and not auth.success_marker:
        log.warning("Login completed but no cookies were set")

    if not seeds:
        seeds.append(target_url)

    return AuthResult(
        ok=True,
        method="form_login",
        message=f"Form login OK (HTTP {response.status_code})",
        seed_urls=seeds,
    )
