from __future__ import annotations

from urllib.parse import urlparse

from core.auth import TargetAuth, apply_target_auth
from core.checks import get_enabled_checks
from core.config import AppConfig
from core.crawler import WebCrawler
from core.http_client import RateLimitedSession
from core.logging_setup import get_logger
from core.models import CrawlResult, Finding, ScanResult, ScanStatus, dedupe_findings

log = get_logger(__name__)


class ScanEngine:
    """Unified scan pipeline used by CLI and dashboard."""

    def __init__(self, config: AppConfig):
        self.config = config

    def run(
        self,
        target_url: str,
        progress_cb=None,
        auth: TargetAuth | None = None,
    ) -> ScanResult:
        def progress(message: str, percent: int) -> None:
            if progress_cb:
                progress_cb(message, percent)
            log.info("[%s%%] %s", percent, message)

        result = ScanResult(target_url=target_url, status=ScanStatus.RUNNING.value)
        host = urlparse(target_url).netloc.lower()
        if not host:
            result.status = ScanStatus.FAILED.value
            result.error = "Invalid target URL"
            return result

        session = RateLimitedSession(self.config, allowed_hosts={host})
        for extra in self.config.allowlist_hosts:
            session.allow_host(extra)

        target_auth = auth or self.config.target_auth

        try:
            if target_auth.enabled():
                progress("Authenticating against target", 5)
                auth_result = apply_target_auth(session, target_url, target_auth)
                result.auth_method = auth_result.method
                result.auth_message = auth_result.message
                if not auth_result.ok:
                    result.status = ScanStatus.FAILED.value
                    result.error = auth_result.message
                    return result
                result.authenticated = auth_result.method != "none"
                extra_seeds = auth_result.seed_urls
            else:
                extra_seeds = []
                result.authenticated = False
                result.auth_method = "none"

            progress("Crawling target", 10)
            crawler = WebCrawler(target_url, self.config, session=session)
            crawl: CrawlResult = crawler.crawl(
                extra_seeds=extra_seeds,
                authenticated=result.authenticated,
            )
            result.pages_crawled = len(crawl.visited_urls)

            checks = get_enabled_checks(self.config.enabled_checks)
            findings: list[Finding] = []
            technologies: list[str] = []

            total = max(len(checks), 1)
            for idx, check in enumerate(checks):
                pct = 20 + int(70 * (idx / total))
                progress(f"Running check: {check.check_id}", pct)
                try:
                    found = check.run(crawl, session, self.config)
                except Exception as exc:  # noqa: BLE001 — isolate check failures
                    log.exception("Check %s failed: %s", check.check_id, exc)
                    continue
                if check.check_id == "tech_detect":
                    technologies = sorted({f.evidence for f in found if f.evidence})
                findings.extend(found)

            result.findings = dedupe_findings(findings)
            result.technologies = technologies
            result.status = ScanStatus.DONE.value
            progress("Scan complete", 100)
            return result
        except Exception as exc:  # noqa: BLE001
            log.exception("Scan failed: %s", exc)
            result.status = ScanStatus.FAILED.value
            result.error = str(exc)
            return result
