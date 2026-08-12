from __future__ import annotations

from core.checks.base import BaseCheck
from core.config import AppConfig, load_data_lines
from core.http_client import RateLimitedSession
from core.models import Confidence, CrawlResult, Finding, Severity


class SqliErrorCheck(BaseCheck):
    check_id = "sqli_error"
    title = "Error-based SQL injection"

    def run(
        self,
        crawl: CrawlResult,
        session: RateLimitedSession,
        config: AppConfig,
    ) -> list[Finding]:
        findings: list[Finding] = []
        payloads = (load_data_lines("sqli_payloads.txt") or ["'", '"'])[: max(1, config.max_payloads)]
        errors = [e.lower() for e in load_data_lines("sql_errors.txt")]
        if not errors:
            errors = ["sql syntax", "mysql_fetch", "sqlite3", "unclosed quotation mark"]

        def matched_error(body: str) -> str | None:
            lower = body.lower()
            for err in errors:
                if err in lower:
                    return err
            return None

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
                    hit = matched_error(response.text or "")
                    if not hit:
                        continue
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Possible SQL injection (error-based)",
                            severity=Severity.CRITICAL.value,
                            confidence=Confidence.MEDIUM.value,
                            url=str(response.url),
                            method="GET",
                            param=param_name,
                            evidence=f"Matched error signature: {hit}",
                            remediation="Use parameterized queries and hide database errors from clients.",
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
                hit = matched_error(response.text or "")
                if hit:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Possible SQL injection in form (error-based)",
                            severity=Severity.CRITICAL.value,
                            confidence=Confidence.MEDIUM.value,
                            url=form.action_url,
                            method=form.method.upper(),
                            evidence=f"Matched error signature: {hit}",
                            remediation="Use parameterized queries and hide database errors from clients.",
                        )
                    )
                    break
        return findings
