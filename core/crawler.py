from __future__ import annotations

from collections import deque
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from core.config import AppConfig
from core.http_client import RateLimitedSession
from core.logging_setup import get_logger
from core.models import CrawlResult, FormTarget, ParamTarget

log = get_logger(__name__)


def normalize_url(url: str) -> str:
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    # Drop fragment; keep query for param discovery, strip for visit identity separately
    return urlunparse((scheme, netloc, path, "", parsed.query, ""))


def url_without_query(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc.lower(), path, "", "", ""))


def same_origin(base: str, other: str) -> bool:
    a = urlparse(base)
    b = urlparse(other)
    return a.scheme == b.scheme and a.netloc.lower() == b.netloc.lower()


class WebCrawler:
    def __init__(self, base_url: str, config: AppConfig, session: RateLimitedSession | None = None):
        self.base_url = normalize_url(base_url.split("?")[0]) if "?" in base_url else normalize_url(base_url)
        # Preserve original if it had useful path
        parsed = urlparse(base_url)
        self.base_url = urlunparse(
            (
                (parsed.scheme or "http").lower(),
                parsed.netloc.lower(),
                parsed.path or "/",
                "",
                "",
                "",
            )
        )
        self.config = config
        host = urlparse(self.base_url).netloc.lower()
        self.session = session or RateLimitedSession(config, allowed_hosts={host})
        self.session.allow_host(host)
        self.visited: set[str] = set()
        self.forms: list[FormTarget] = []
        self._form_keys: set[str] = set()
        self.params: list[ParamTarget] = []
        self._param_keys: set[str] = set()
        self.seed_html = ""
        self.seed_headers: dict[str, str] = {}

    def crawl(self, extra_seeds: list[str] | None = None, authenticated: bool = False) -> CrawlResult:
        log.info("Crawling %s (max_pages=%s, max_depth=%s)", self.base_url, self.config.max_pages, self.config.max_depth)
        queue: deque[tuple[str, int]] = deque([(self.base_url, 0)])
        for seed in extra_seeds or []:
            if same_origin(self.base_url, seed):
                queue.append((seed, 0))
        pages = 0

        while queue and pages < self.config.max_pages:
            current, depth = queue.popleft()
            visit_key = url_without_query(current)
            if visit_key in self.visited:
                continue
            self.visited.add(visit_key)

            response = self.session.get(current)
            if response is None:
                continue

            if pages == 0:
                self.seed_html = response.text or ""
                self.seed_headers = {k: v for k, v in response.headers.items()}

            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                pages += 1
                continue

            html = response.text or ""
            self._extract_forms(current, html)
            self._extract_query_params(response.url)

            if depth < self.config.max_depth:
                for link in self._extract_links(current, html):
                    link_key = url_without_query(link)
                    if link_key not in self.visited:
                        queue.append((link, depth + 1))

            pages += 1

        return CrawlResult(
            base_url=self.base_url,
            visited_urls=sorted(self.visited),
            forms=list(self.forms),
            params=list(self.params),
            seed_html=self.seed_html,
            seed_headers=self.seed_headers,
            authenticated=authenticated,
        )

    def _extract_links(self, page_url: str, html: str) -> list[str]:
        soup = BeautifulSoup(html, "html.parser")
        found: list[str] = []
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href")
            if not href:
                continue
            full = urljoin(page_url, href)
            if not same_origin(self.base_url, full):
                continue
            if urlparse(full).scheme not in {"http", "https"}:
                continue
            found.append(normalize_url(full))
            if "?" in full:
                self._extract_query_params(full)
        for tag in soup.find_all(["form"]):
            action = tag.get("action")
            if action:
                full = urljoin(page_url, action)
                if same_origin(self.base_url, full):
                    found.append(url_without_query(full))
        return found

    def _extract_forms(self, page_url: str, html: str) -> None:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action")
            method = (form.get("method") or "get").lower()
            action_url = urljoin(page_url, action) if action else page_url
            if not same_origin(self.base_url, action_url):
                continue
            inputs: list[dict[str, str]] = []
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if not name:
                    continue
                inputs.append(
                    {
                        "name": name,
                        "type": (input_tag.get("type") or "text").lower(),
                    }
                )
            key = f"{action_url}|{method}|{','.join(sorted(i['name'] for i in inputs))}"
            if key in self._form_keys:
                continue
            self._form_keys.add(key)
            self.forms.append(
                FormTarget(
                    page_url=page_url,
                    action_url=url_without_query(action_url),
                    method=method,
                    inputs=inputs,
                )
            )

    def _extract_query_params(self, url: str) -> None:
        parsed = urlparse(url)
        if not parsed.query:
            return
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return
        base = url_without_query(url)
        key = f"{base}|{','.join(sorted(params))}"
        if key in self._param_keys:
            return
        self._param_keys.add(key)
        self.params.append(ParamTarget(url=base, params=params))
