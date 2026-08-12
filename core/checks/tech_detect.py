from __future__ import annotations

import re

from core.checks.base import BaseCheck
from core.config import AppConfig
from core.http_client import RateLimitedSession
from core.models import Confidence, CrawlResult, Finding, Severity


class TechDetectCheck(BaseCheck):
    check_id = "tech_detect"
    title = "Technology fingerprint"

    # Prefer specific signatures; generic ones get low confidence.
    STRICT = {
        "WordPress": (r"wp-content/|wp-includes/", Confidence.HIGH.value),
        "Joomla": (r'content="Joomla', Confidence.HIGH.value),
        "Angular": (r"ng-version=|ng-app=", Confidence.HIGH.value),
        "ASP.NET": (r"__VIEWSTATE|\.aspx\b", Confidence.HIGH.value),
        "Laravel": (r"laravel_session|XSRF-TOKEN", Confidence.MEDIUM.value),
        "Django": (r"csrfmiddlewaretoken|django", Confidence.MEDIUM.value),
    }
    LOOSE = {
        "React": (r"data-reactroot|__NEXT_DATA__", Confidence.MEDIUM.value),
        "Vue.js": (r"data-v-[a-f0-9]{5,}|__VUE__", Confidence.MEDIUM.value),
        "Bootstrap": (r"bootstrap(\.min)?\.(css|js)", Confidence.MEDIUM.value),
        "jQuery": (r"jquery[-.]?\d|jquery\.min\.js", Confidence.LOW.value),
        "PHP": (r"\.php\b", Confidence.LOW.value),
    }

    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        html = crawl.seed_html
        headers = crawl.seed_headers
        if not html:
            response = session.get(crawl.base_url)
            if response is None:
                return []
            html = response.text or ""
            headers = {k: v for k, v in response.headers.items()}

        detected: list[tuple[str, str]] = []
        server = headers.get("Server", headers.get("server", ""))
        powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
        if "nginx" in server.lower():
            detected.append(("Nginx", Confidence.HIGH.value))
        if "apache" in server.lower():
            detected.append(("Apache", Confidence.HIGH.value))
        if "php" in powered.lower():
            detected.append(("PHP", Confidence.HIGH.value))

        for tech, (pattern, confidence) in {**self.STRICT, **self.LOOSE}.items():
            if any(t == tech for t, _ in detected):
                continue
            if re.search(pattern, html, re.IGNORECASE):
                detected.append((tech, confidence))

        # Store techs on crawl via engine; emit info findings
        findings: list[Finding] = []
        for tech, confidence in detected:
            findings.append(
                Finding(
                    check_id=self.check_id,
                    title=f"Technology detected: {tech}",
                    severity=Severity.INFO.value,
                    confidence=confidence,
                    url=crawl.base_url,
                    evidence=tech,
                    remediation="Informational only — review exposed stack fingerprints.",
                )
            )
        return findings
