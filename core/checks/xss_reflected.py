from __future__ import annotations

import re
from uuid import uuid4

from core.checks.base import BaseCheck
from core.config import AppConfig, load_data_lines
from core.http_client import RateLimitedSession
from core.models import Confidence, CrawlResult, Finding, Severity


class XssReflectedCheck(BaseCheck):
    check_id = "xss_reflected"
    title = "Reflected XSS"

    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        findings: list[Finding] = []
        marker = uuid4().hex[:8]
        payloads = [
            p.replace("{{MARKER}}", marker) for p in load_data_lines("xss_payloads.txt")
        ][: max(1, config.max_payloads)]
        if not payloads:
            payloads = [f"webguard-xss-probe-{marker}"]

        param_budget = max(1, config.max_fuzz_params)
        form_budget = max(1, config.max_fuzz_forms)
        tested_params = 0

        for item in crawl.params:
            if tested_params >= param_budget:
                break
            for param_name in item.params:
                if tested_params >= param_budget:
                    break
                tested_params += 1
                for payload in payloads:
                    test_params = {
                        k: (payload if k == param_name else (v[0] if v else ""))
                        for k, v in item.params.items()
                    }
                    response = session.get(item.url, params=test_params)
                    if response is None:
                        continue
                    body = response.text or ""
                    if payload not in body:
                        continue
                    if re.search(r"<script[^>]*>.*" + re.escape(payload), body, re.I | re.S):
                        confidence = Confidence.HIGH.value
                    elif "<" in payload:
                        confidence = Confidence.HIGH.value
                    else:
                        confidence = Confidence.MEDIUM.value
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Possible reflected XSS",
                            severity=Severity.HIGH.value,
                            confidence=confidence,
                            url=str(response.url),
                            method="GET",
                            param=param_name,
                            evidence=payload[:200],
                            remediation="Encode output contextually and apply a strict CSP.",
                        )
                    )
                    break

        for form in crawl.forms[:form_budget]:
            if not form.inputs:
                continue
            for payload in payloads:
                data = {inp["name"]: payload for inp in form.inputs if inp["name"]}
                if form.method == "post":
                    response = session.post(form.action_url, data=data)
                else:
                    response = session.get(form.action_url, params=data)
                if response is None:
                    continue
                if payload in (response.text or ""):
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Possible reflected XSS in form",
                            severity=Severity.HIGH.value,
                            confidence=Confidence.MEDIUM.value,
                            url=form.action_url,
                            method=form.method.upper(),
                            evidence=payload[:200],
                            remediation="Encode output contextually and apply a strict CSP.",
                        )
                    )
                    break
        return findings
