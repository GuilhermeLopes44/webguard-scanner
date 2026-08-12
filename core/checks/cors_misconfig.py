from __future__ import annotations

from core.checks.base import BaseCheck
from core.config import AppConfig
from core.http_client import RateLimitedSession
from core.models import Confidence, CrawlResult, Finding, Severity


class CorsMisconfigCheck(BaseCheck):
    check_id = "cors_misconfig"
    title = "CORS misconfiguration"

    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        findings: list[Finding] = []
        origin = "https://evil.webguard.invalid"
        response = session.get(crawl.base_url, headers={"Origin": origin})
        if response is None:
            return findings

        acao = response.headers.get("Access-Control-Allow-Origin", "")
        acac = response.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="CORS allows any origin",
                    severity=Severity.LOW.value,
                    confidence=Confidence.HIGH.value,
                    url=crawl.base_url,
                    evidence="Access-Control-Allow-Origin: *",
                    remediation="Avoid wildcard ACAO for sensitive APIs; reflect only trusted origins.",
                )
            )
        if acao == origin:
            severity = Severity.HIGH.value if acac.lower() == "true" else Severity.MEDIUM.value
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title="CORS reflects arbitrary Origin",
                    severity=severity,
                    confidence=Confidence.HIGH.value,
                    url=crawl.base_url,
                    evidence=f"ACAO={acao}; ACAC={acac or '-'}",
                    remediation="Do not reflect untrusted Origin values, especially with credentials.",
                )
            )
        return findings
