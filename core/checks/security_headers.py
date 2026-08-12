from __future__ import annotations

from core.checks.base import BaseCheck
from core.config import AppConfig
from core.http_client import RateLimitedSession
from core.models import Confidence, CrawlResult, Finding, Severity


class SecurityHeadersCheck(BaseCheck):
    check_id = "security_headers"
    title = "Security headers"

    HEADERS = {
        "Strict-Transport-Security": (
            Severity.MEDIUM.value,
            "Enable HSTS to prevent protocol downgrade attacks.",
        ),
        "Content-Security-Policy": (
            Severity.MEDIUM.value,
            "Define a Content-Security-Policy to reduce XSS impact.",
        ),
        "X-Frame-Options": (
            Severity.LOW.value,
            "Set X-Frame-Options or frame-ancestors in CSP against clickjacking.",
        ),
        "X-Content-Type-Options": (
            Severity.LOW.value,
            "Set X-Content-Type-Options: nosniff.",
        ),
        "Referrer-Policy": (
            Severity.INFO.value,
            "Set a Referrer-Policy to limit referrer leakage.",
        ),
    }

    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        findings: list[Finding] = []
        headers = {k.lower(): v for k, v in crawl.seed_headers.items()}
        if not headers:
            response = session.get(crawl.base_url)
            if response is None:
                return findings
            headers = {k.lower(): v for k, v in response.headers.items()}

        for header, (severity, remediation) in self.HEADERS.items():
            value = headers.get(header.lower())
            if value is None:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"Missing security header: {header}",
                        severity=severity,
                        confidence=Confidence.HIGH.value,
                        url=crawl.base_url,
                        method="GET",
                        evidence=f"Response did not include {header}",
                        remediation=remediation,
                    )
                )
                continue
            if header == "X-Content-Type-Options" and "nosniff" not in value.lower():
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Weak X-Content-Type-Options",
                        severity=Severity.LOW.value,
                        confidence=Confidence.HIGH.value,
                        url=crawl.base_url,
                        method="GET",
                        evidence=f"{header}: {value}",
                        remediation="Use X-Content-Type-Options: nosniff.",
                    )
                )
            if header == "Content-Security-Policy" and value.strip() in {"*", "default-src *"}:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Weak Content-Security-Policy",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.MEDIUM.value,
                        url=crawl.base_url,
                        method="GET",
                        evidence=f"{header}: {value}",
                        remediation="Tighten CSP directives; avoid wildcard defaults.",
                    )
                )
        return findings
