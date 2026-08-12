from __future__ import annotations

from urllib.parse import urlparse

from core.checks.base import BaseCheck
from core.config import AppConfig
from core.http_client import RateLimitedSession
from core.models import Confidence, CrawlResult, Finding, Severity

REDIRECT_PARAMS = {
    "url",
    "next",
    "redirect",
    "redirect_uri",
    "return",
    "returnUrl",
    "return_url",
    "dest",
    "destination",
    "continue",
    "goto",
    "target",
    "rurl",
}


class OpenRedirectCheck(BaseCheck):
    check_id = "open_redirect"
    title = "Open redirect"

    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        findings: list[Finding] = []
        probe = "https://example.com/webguard-redirect-probe"
        budget = max(1, config.max_fuzz_params)
        tested = 0

        for item in crawl.params:
            if tested >= budget:
                break
            candidates = [p for p in item.params if p.lower() in {x.lower() for x in REDIRECT_PARAMS}]
            if not candidates:
                for name, values in item.params.items():
                    joined = " ".join(values)
                    if "http://" in joined or "https://" in joined or joined.startswith("/"):
                        candidates.append(name)
            for param_name in candidates:
                if tested >= budget:
                    break
                tested += 1
                test_params = {
                    k: (probe if k == param_name else (v[0] if v else ""))
                    for k, v in item.params.items()
                }
                response = session.get(item.url, params=test_params, allow_redirects=False)
                if response is None:
                    continue
                location = response.headers.get("Location", "")
                if not location:
                    continue
                if "example.com/webguard-redirect-probe" in location:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Possible open redirect",
                            severity=Severity.MEDIUM.value,
                            confidence=Confidence.HIGH.value,
                            url=item.url,
                            method="GET",
                            param=param_name,
                            evidence=f"Location: {location}",
                            remediation="Validate redirect targets against an allowlist of relative paths/hosts.",
                        )
                    )
                else:
                    # Absolute external redirect to different host
                    loc_host = urlparse(location).netloc.lower()
                    base_host = urlparse(crawl.base_url).netloc.lower()
                    if loc_host and loc_host != base_host and "example.com" in loc_host:
                        findings.append(
                            Finding(
                                check_id=self.check_id,
                                title="Possible open redirect",
                                severity=Severity.MEDIUM.value,
                                confidence=Confidence.MEDIUM.value,
                                url=item.url,
                                method="GET",
                                param=param_name,
                                evidence=f"Location: {location}",
                                remediation="Validate redirect targets against an allowlist.",
                            )
                        )
        return findings
