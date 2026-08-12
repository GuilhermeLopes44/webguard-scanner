from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import Finding, ScanResult, SEVERITY_RANK


class ReportGenerator:
    def __init__(self, result: ScanResult):
        self.result = result

    def to_json_dict(self) -> dict[str, Any]:
        data = self.result.to_dict()
        data["executive_summary"] = self.executive_summary_text()
        return data

    def write_json(self, path: str | Path) -> Path:
        out = Path(path)
        out.write_text(
            json.dumps(self.to_json_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return out

    def executive_summary_text(self) -> str:
        counts = self.result.severity_counts()
        high_plus = counts["critical"] + counts["high"]
        auth = "authenticated" if self.result.authenticated else "unauthenticated"
        if not self.result.findings:
            risk = "No automated findings were reported with the current check set."
        elif high_plus:
            risk = (
                f"{high_plus} high/critical finding(s) require prioritized remediation."
            )
        elif counts["medium"]:
            risk = "Medium-severity issues were found; plan remediation in the next sprint."
        else:
            risk = "Only low/info findings were reported."

        top = sorted(
            self.result.findings,
            key=lambda f: SEVERITY_RANK.get(f.severity, 0),
            reverse=True,
        )[:5]
        top_lines = "\n".join(
            f"- [{f.severity.upper()}] {f.title} ({f.check_id}) @ {f.url}" for f in top
        ) or "- None"

        return (
            f"Target: {self.result.target_url}\n"
            f"Mode: {auth}"
            f"{f' ({self.result.auth_method})' if self.result.auth_method else ''}\n"
            f"Pages crawled: {self.result.pages_crawled}\n"
            f"Technologies: {', '.join(self.result.technologies) or 'n/a'}\n"
            f"Findings: {len(self.result.findings)} "
            f"(critical={counts['critical']}, high={counts['high']}, "
            f"medium={counts['medium']}, low={counts['low']}, info={counts['info']})\n"
            f"Risk narrative: {risk}\n"
            f"Top findings:\n{top_lines}\n"
        )

    def to_markdown(self) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        counts = self.result.severity_counts()
        lines = [
            "# WebGuard Executive Report",
            "",
            f"**Generated:** {now}  ",
            f"**Target:** `{self.result.target_url}`  ",
            f"**Status:** {self.result.status}  ",
            f"**Authenticated:** {'yes' if self.result.authenticated else 'no'}"
            + (f" ({self.result.auth_method})" if self.result.auth_method else ""),
            "",
            "## Summary",
            "",
            self.executive_summary_text().replace("\n", "  \n"),
            "",
            "## Severity breakdown",
            "",
            "| Severity | Count |",
            "|---|---:|",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| {sev} | {counts[sev]} |")
        lines.extend(["", "## Findings", ""])
        if not self.result.findings:
            lines.append("_No findings._")
        else:
            for f in sorted(
                self.result.findings,
                key=lambda x: SEVERITY_RANK.get(x.severity, 0),
                reverse=True,
            ):
                lines.extend(
                    [
                        f"### [{f.severity.upper()}] {f.title}",
                        "",
                        f"- **Check:** `{f.check_id}`",
                        f"- **Confidence:** {f.confidence}",
                        f"- **URL:** `{f.url}`",
                        f"- **Method:** {f.method}"
                        + (f" · param `{f.param}`" if f.param else ""),
                        f"- **Evidence:** `{f.evidence}`",
                        f"- **Remediation:** {f.remediation or 'n/a'}",
                        "",
                    ]
                )
        lines.extend(
            [
                "## Limitations",
                "",
                "This is an automated DAST report for authorized testing. It does not replace "
                "a full manual penetration test (business logic, complex auth flows, or "
                "confirmed exploitation beyond HTTP evidence).",
                "",
            ]
        )
        return "\n".join(lines)

    def write_markdown(self, path: str | Path) -> Path:
        out = Path(path)
        out.write_text(self.to_markdown(), encoding="utf-8")
        return out

    def to_html(self) -> str:
        counts = self.result.severity_counts()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        rows = []
        for f in sorted(
            self.result.findings,
            key=lambda x: SEVERITY_RANK.get(x.severity, 0),
            reverse=True,
        ):
            rows.append(
                "<tr>"
                f"<td><span class='sev {html.escape(f.severity)}'>{html.escape(f.severity)}</span></td>"
                f"<td>{html.escape(f.title)}<div class='muted'>{html.escape(f.check_id)} · {html.escape(f.confidence)}</div></td>"
                f"<td class='mono'>{html.escape(f.url)}</td>"
                f"<td class='mono'>{html.escape(f.evidence[:180])}</td>"
                f"<td>{html.escape(f.remediation or '')}</td>"
                "</tr>"
            )
        body_rows = "\n".join(rows) or "<tr><td colspan='5'>No findings</td></tr>"
        summary = html.escape(self.executive_summary_text()).replace("\n", "<br>")
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WebGuard Executive Report</title>
<style>
body {{ font-family: Segoe UI, system-ui, sans-serif; margin: 32px; color: #111; background: #fafafa; }}
h1 {{ margin-bottom: 4px; }}
.meta {{ color: #555; margin-bottom: 24px; }}
.cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0 28px; }}
.card {{ background: #fff; border: 1px solid #ddd; padding: 14px 18px; min-width: 110px; }}
.card strong {{ display: block; font-size: 22px; }}
table {{ width: 100%; border-collapse: collapse; background: #fff; }}
th, td {{ border: 1px solid #e5e5e5; padding: 10px; vertical-align: top; text-align: left; font-size: 14px; }}
th {{ background: #f3f3f3; }}
.mono {{ font-family: ui-monospace, Consolas, monospace; font-size: 12px; word-break: break-all; }}
.muted {{ color: #777; font-size: 12px; margin-top: 4px; }}
.sev {{ text-transform: uppercase; font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 3px; }}
.critical, .high {{ background: #fee2e2; color: #991b1b; }}
.medium {{ background: #ffedd5; color: #9a3412; }}
.low {{ background: #dbeafe; color: #1e40af; }}
.info {{ background: #e5e7eb; color: #374151; }}
.box {{ background: #fff; border: 1px solid #ddd; padding: 16px; margin-bottom: 24px; }}
footer {{ margin-top: 28px; color: #777; font-size: 12px; }}
</style>
</head>
<body>
<h1>WebGuard Executive Report</h1>
<div class="meta">Generated {html.escape(now)} · Target {html.escape(self.result.target_url)} ·
Auth: {"yes" if self.result.authenticated else "no"}</div>
<div class="cards">
  <div class="card"><strong>{len(self.result.findings)}</strong>Findings</div>
  <div class="card"><strong>{counts['critical']}</strong>Critical</div>
  <div class="card"><strong>{counts['high']}</strong>High</div>
  <div class="card"><strong>{counts['medium']}</strong>Medium</div>
  <div class="card"><strong>{self.result.pages_crawled}</strong>Pages</div>
</div>
<div class="box"><h2>Executive summary</h2><p>{summary}</p></div>
<table>
<thead><tr><th>Severity</th><th>Finding</th><th>URL</th><th>Evidence</th><th>Remediation</th></tr></thead>
<tbody>
{body_rows}
</tbody>
</table>
<footer>Automated DAST for authorized testing only. Not a substitute for a full manual pentest.</footer>
</body>
</html>"""

    def write_html(self, path: str | Path) -> Path:
        out = Path(path)
        out.write_text(self.to_html(), encoding="utf-8")
        return out

    def to_csv_string(self, scan_id: int | None = None) -> str:
        output = io.StringIO()
        writer = csv.writer(output, delimiter=";", dialect="excel")
        writer.writerow(
            [
                "scan_id",
                "target",
                "check_id",
                "title",
                "severity",
                "confidence",
                "url",
                "method",
                "param",
                "evidence",
                "remediation",
            ]
        )
        techs = ", ".join(self.result.technologies)
        if not self.result.findings:
            writer.writerow(
                [
                    scan_id or "",
                    self.result.target_url,
                    "",
                    "No findings",
                    "info",
                    "high",
                    self.result.target_url,
                    "-",
                    "",
                    techs or "-",
                    "",
                ]
            )
        else:
            for f in self.result.findings:
                writer.writerow(
                    [
                        scan_id or "",
                        self.result.target_url,
                        f.check_id,
                        f.title,
                        f.severity,
                        f.confidence,
                        f.url,
                        f.method,
                        f.param or "",
                        f.evidence,
                        f.remediation,
                    ]
                )
        return output.getvalue()

    def to_sarif(self) -> dict[str, Any]:
        rules = {}
        results = []
        for finding in self.result.findings:
            rules[finding.check_id] = {
                "id": finding.check_id,
                "name": finding.check_id,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.remediation or finding.title},
                "defaultConfiguration": {
                    "level": _sarif_level(finding.severity),
                },
            }
            results.append(
                {
                    "ruleId": finding.check_id,
                    "level": _sarif_level(finding.severity),
                    "message": {"text": finding.title},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.url},
                            }
                        }
                    ],
                    "properties": {
                        "confidence": finding.confidence,
                        "param": finding.param,
                        "evidence": finding.evidence,
                    },
                }
            )
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "WebGuard",
                            "informationUri": "https://github.com/GuilhermeLopes44/webguard-scanner",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def write_sarif(self, path: str | Path) -> Path:
        out = Path(path)
        out.write_text(json.dumps(self.to_sarif(), indent=2), encoding="utf-8")
        return out


def _sarif_level(severity: str) -> str:
    rank = SEVERITY_RANK.get(severity, 1)
    if rank >= 4:
        return "error"
    if rank == 3:
        return "warning"
    return "note"


def findings_from_dicts(items: list[dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    for item in items:
        out.append(
            Finding(
                id=item.get("id", ""),
                check_id=item.get("check_id", "unknown"),
                title=item.get("title", ""),
                severity=item.get("severity", "info"),
                confidence=item.get("confidence", "low"),
                url=item.get("url", ""),
                method=item.get("method", "GET"),
                param=item.get("param"),
                evidence=item.get("evidence", ""),
                remediation=item.get("remediation", ""),
            )
        )
    return out
