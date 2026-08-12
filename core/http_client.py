from __future__ import annotations

import threading
import time
from typing import Any
from urllib.parse import urlparse

import requests

from core.config import AppConfig
from core.logging_setup import get_logger

log = get_logger(__name__)


class RateLimitedSession:
    """HTTP session with rate limiting and host allowlist."""

    def __init__(self, config: AppConfig, allowed_hosts: set[str] | None = None):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent})
        self.allowed_hosts = {h.lower() for h in (allowed_hosts or set())}
        for host in config.allowlist_hosts:
            self.allowed_hosts.add(host.lower())
        self._lock = threading.Lock()
        self._min_interval = 1.0 / max(config.rate_limit_rps, 0.1)
        self._last_request = 0.0

    def allow_host(self, host: str) -> None:
        self.allowed_hosts.add(host.lower())

    def _wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.monotonic()

    def _host_allowed(self, url: str) -> bool:
        host = (urlparse(url).netloc or "").lower()
        if not self.allowed_hosts:
            return True
        return host in self.allowed_hosts

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response | None:
        if not self._host_allowed(url):
            log.warning("Blocked request to non-allowlisted host: %s", url)
            return None
        kwargs.setdefault("timeout", self.config.timeout)
        kwargs.setdefault("allow_redirects", True)
        self._wait()
        try:
            return self.session.request(method, url, **kwargs)
        except requests.RequestException as exc:
            log.debug("Request failed %s %s: %s", method, url, exc)
            return None

    def get(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response | None:
        return self.request("POST", url, **kwargs)
