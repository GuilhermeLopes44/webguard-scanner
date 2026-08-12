from __future__ import annotations

from urllib.parse import urljoin

from core.checks.base import BaseCheck
from core.config import AppConfig, load_data_lines
from core.http_client import RateLimitedSession
from core.models import Confidence, CrawlResult, Finding, Severity


class SensitivePathsCheck(BaseCheck):
    check_id = "sensitive_paths"
    title = "Sensitive path exposure"

    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        findings: list[Finding] = []
        paths = load_data_lines("sensitive_paths.txt")[:12]
        base = crawl.base_url.rstrip("/") + "/"

        for path in paths:
            url = urljoin(base, path.lstrip("/"))
            # urljoin with absolute path replaces path — handle leading slash paths
            if path.startswith("/"):
                from urllib.parse import urlparse, urlunparse

                parsed = urlparse(crawl.base_url)
                url = urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

            response = session.get(url, allow_redirects=False)
            if response is None:
                continue
            if response.status_code != 200:
                continue
            body = (response.text or "")[:500].lower()
            content_type = response.headers.get("Content-Type", "").lower()
            # Avoid treating soft-404 HTML landing pages as hits when possible
            interesting = False
            if path.endswith(".git/HEAD") and "refs/" in body:
                interesting = True
            elif ".env" in path and ("=" in body and not body.strip().startswith("<!")):
                interesting = True
            elif any(path.endswith(ext) for ext in (".sql", ".zip", ".bak", ".json")):
                interesting = True
            elif "phpinfo" in path and "phpinfo()" in body:
                interesting = True
            elif "text/plain" in content_type or "application/json" in content_type:
                interesting = True
            elif len(body) > 0 and "<html" not in body:
                interesting = True

            if not interesting:
                continue

            findings.append(
                Finding(
                    check_id=self.check_id,
                    title=f"Sensitive path accessible: {path}",
                    severity=Severity.HIGH.value,
                    confidence=Confidence.MEDIUM.value,
                    url=url,
                    method="GET",
                    evidence=f"HTTP {response.status_code}; content-type={content_type or '-'}",
                    remediation="Remove or block sensitive files from public web roots.",
                )
            )
        return findings
