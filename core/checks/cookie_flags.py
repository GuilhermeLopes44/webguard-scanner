from __future__ import annotations

from core.checks.base import BaseCheck
from core.config import AppConfig
from core.http_client import RateLimitedSession
from core.models import Confidence, CrawlResult, Finding, Severity


class CookieFlagsCheck(BaseCheck):
    check_id = "cookie_flags"
    title = "Cookie security flags"

    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        findings: list[Finding] = []
        response = session.get(crawl.base_url)
        if response is None:
            return findings

        for cookie in response.cookies:
            name = cookie.name
            if not cookie.secure:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"Cookie without Secure flag: {name}",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.HIGH.value,
                        url=crawl.base_url,
                        evidence=f"Set-Cookie {name} missing Secure",
                        remediation="Set the Secure flag so the cookie is only sent over HTTPS.",
                    )
                )

            # requests exposes httponly via _rest / has_nonstandard_attr inconsistently
            raw = str(getattr(cookie, "_rest", {}) or {})
            httponly = bool(
                getattr(cookie, "has_nonstandard_attr", lambda _x: False)("HttpOnly")
                or getattr(cookie, "has_nonstandard_attr", lambda _x: False)("httponly")
                or "httponly" in raw.lower()
            )
            if not httponly:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"Cookie without HttpOnly flag: {name}",
                        severity=Severity.MEDIUM.value,
                        confidence=Confidence.MEDIUM.value,
                        url=crawl.base_url,
                        evidence=f"Set-Cookie {name} missing HttpOnly",
                        remediation="Set HttpOnly to reduce cookie theft via XSS.",
                    )
                )

            samesite = None
            rest = getattr(cookie, "_rest", {}) or {}
            for key, value in rest.items():
                if str(key).lower() == "samesite":
                    samesite = str(value)
            if samesite is None:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title=f"Cookie without SameSite: {name}",
                        severity=Severity.LOW.value,
                        confidence=Confidence.MEDIUM.value,
                        url=crawl.base_url,
                        evidence=f"Set-Cookie {name} missing SameSite",
                        remediation="Set SameSite=Lax or Strict to mitigate CSRF.",
                    )
                )
        return findings
