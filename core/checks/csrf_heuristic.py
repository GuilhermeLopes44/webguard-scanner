from __future__ import annotations

from core.checks.base import BaseCheck
from core.config import AppConfig
from core.http_client import RateLimitedSession
from core.models import Confidence, CrawlResult, Finding, Severity

CSRF_NAMES = {
    "csrf",
    "csrf_token",
    "csrfmiddlewaretoken",
    "_csrf",
    "_token",
    "authenticity_token",
    "xsrf",
    "__requestverificationtoken",
}


class CsrfHeuristicCheck(BaseCheck):
    check_id = "csrf_heuristic"
    title = "CSRF token heuristic"

    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for form in crawl.forms:
            if form.method != "post":
                continue
            names = {inp["name"].lower() for inp in form.inputs if inp.get("name")}
            if names & CSRF_NAMES:
                continue
            # Heuristic only — many apps use header-based CSRF
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="POST form without obvious CSRF token",
                    severity=Severity.LOW.value,
                    confidence=Confidence.LOW.value,
                    url=form.action_url,
                    method="POST",
                    evidence=f"Inputs: {', '.join(sorted(names)) or '(none)'}",
                    remediation="Ensure anti-CSRF tokens or SameSite cookies protect state-changing forms.",
                )
            )
        return findings
