from __future__ import annotations

import json
import os
import sys
from functools import wraps
from typing import Any, Callable

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.config import AppConfig, get_auth_token, load_config
from core.auth import TargetAuth
from core.job_runner import enqueue_scan
from core.logging_setup import setup_logging
from core.models import ScanResult
from core.reporter import ReportGenerator, findings_from_dicts
from db.database import get_all_scans, get_scan_by_id, init_db


def _authorized() -> bool:
    token = get_auth_token()
    if not token:
        return True
    header = request.headers.get("X-WebGuard-Token", "")
    form_token = request.form.get("token", "")
    query_token = request.args.get("token", "")
    return token in {header, form_token, query_token}


def require_token(view: Callable) -> Callable:
    @wraps(view)
    def wrapper(*args: Any, **kwargs: Any):
        if not _authorized():
            return jsonify({"error": "Unauthorized — set WEBGUARD_TOKEN and pass it"}), 401
        return view(*args, **kwargs)

    return wrapper


SEVERITY_PT = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Média",
    "low": "Baixa",
    "info": "Informativa",
}

CHECK_PT = {
    "security_headers": "Cabeçalhos de segurança",
    "cookie_flags": "Flags de cookie",
    "tech_detect": "Tecnologias",
    "xss_reflected": "XSS refletido",
    "sqli_error": "SQL Injection",
    "open_redirect": "Open redirect",
    "cors_misconfig": "CORS",
    "sensitive_paths": "Caminhos sensíveis",
    "csrf_heuristic": "CSRF (heurística)",
}

STATUS_PT = {
    "queued": "Na fila",
    "running": "Em andamento",
    "done": "Concluído",
    "failed": "Falhou",
}


def _enrich_scan(scan: dict[str, Any]) -> dict[str, Any]:
    findings = scan.get("findings") or []
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        f["severity_pt"] = SEVERITY_PT.get(sev, sev)
        f["confidence_pt"] = {
            "high": "Alta",
            "medium": "Média",
            "low": "Baixa",
        }.get((f.get("confidence") or "").lower(), f.get("confidence") or "-")
        f["check_pt"] = CHECK_PT.get(f.get("check_id") or "", f.get("check_id") or "Outro")

    rank_order = ["critical", "high", "medium", "low", "info"]
    max_sev = "none"
    for sev in rank_order:
        if sev_counts[sev]:
            max_sev = sev
            break

    scan["sev_counts"] = sev_counts
    scan["max_sev"] = max_sev
    scan["max_sev_pt"] = SEVERITY_PT.get(max_sev, "Sem falhas")
    scan["status_pt"] = STATUS_PT.get(scan.get("status") or "", scan.get("status") or "-")
    scan["top_findings"] = sorted(
        findings,
        key=lambda x: {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
            (x.get("severity") or "info").lower(), 0
        ),
        reverse=True,
    )[:3]
    return scan


def create_app(config: AppConfig | None = None) -> Flask:
    setup_logging()
    cfg = config or load_config()
    app = Flask(__name__)
    app.config["WEBGUARD_CONFIG"] = cfg
    init_db()

    @app.route("/")
    def index():
        scans = [_enrich_scan(s) for s in get_all_scans()]
        sev_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        vuln_types: dict[str, int] = {}
        total_vulns = 0
        for scan in scans:
            total_vulns += scan.get("total") or 0
            for k, v in (scan.get("sev_counts") or {}).items():
                sev_totals[k] = sev_totals.get(k, 0) + v
            for finding in scan.get("findings") or []:
                label = finding.get("check_pt") or CHECK_PT.get(finding.get("check_id") or "", "Outros")
                if finding.get("check_id") == "tech_detect":
                    continue
                vuln_types[label] = vuln_types.get(label, 0) + 1

        stats = {
            "total_scans": len(scans),
            "total_vulns": total_vulns,
            "critical": sev_totals["critical"],
            "high": sev_totals["high"],
            "medium": sev_totals["medium"],
            "low": sev_totals["low"] + sev_totals["info"],
            "chart_labels": json.dumps(list(vuln_types.keys()), ensure_ascii=False),
            "chart_data": json.dumps(list(vuln_types.values())),
        }
        return render_template(
            "index.html",
            scans=scans,
            stats=stats,
            auth_required=bool(get_auth_token()),
        )

    @app.route("/scan", methods=["POST"])
    @require_token
    def scan():
        target_url = (request.form.get("target_url") or "").strip()
        if not target_url:
            return redirect(url_for("index"))
        cfg: AppConfig = app.config["WEBGUARD_CONFIG"]
        seed_paths = [
            p.strip()
            for p in (request.form.get("seed_paths") or "").split(",")
            if p.strip()
        ]
        auth = TargetAuth(
            login_url=(request.form.get("login_url") or "").strip() or None,
            username=(request.form.get("username") or "").strip() or None,
            password=request.form.get("password") or None,
            username_field=(request.form.get("username_field") or "username").strip(),
            password_field=(request.form.get("password_field") or "password").strip(),
            cookie=(request.form.get("cookie") or "").strip() or None,
            authorization=(request.form.get("auth_header") or "").strip() or None,
            success_marker=(request.form.get("success_marker") or "").strip() or None,
            seed_paths=seed_paths,
        )
        # Avoid storing empty password as enabled auth accidentally
        if auth.password == "":
            auth.password = None
        scan_id = enqueue_scan(target_url, cfg, auth=auth)
        return redirect(url_for("index", active_scan=scan_id))

    @app.route("/api/scans/<int:scan_id>")
    @require_token
    def api_scan(scan_id: int):
        scan = get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"error": "not found"}), 404
        return jsonify(scan)

    @app.route("/api/scans")
    @require_token
    def api_scans():
        return jsonify(get_all_scans())

    def _result_from_scan(scan: dict[str, Any]) -> ScanResult:
        return ScanResult(
            target_url=scan["target_url"],
            findings=findings_from_dicts(scan.get("findings") or []),
            technologies=scan.get("technologies") or [],
            pages_crawled=scan.get("pages_crawled") or 0,
            status=scan.get("status") or "done",
            authenticated=bool(scan.get("authenticated")),
            auth_method=scan.get("auth_method"),
            auth_message=scan.get("auth_message"),
        )

    @app.route("/export/<int:scan_id>.csv")
    @app.route("/export/<int:scan_id>")
    @require_token
    def export_csv(scan_id: int):
        scan = get_scan_by_id(scan_id)
        if not scan:
            return "Report not found", 404
        csv_data = ReportGenerator(_result_from_scan(scan)).to_csv_string(scan_id=scan_id)
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=WebGuard_Scan_{scan_id}.csv"},
        )

    @app.route("/export/<int:scan_id>.json")
    @require_token
    def export_json(scan_id: int):
        scan = get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"error": "not found"}), 404
        return jsonify(ReportGenerator(_result_from_scan(scan)).to_json_dict())

    @app.route("/export/<int:scan_id>.sarif")
    @require_token
    def export_sarif(scan_id: int):
        scan = get_scan_by_id(scan_id)
        if not scan:
            return jsonify({"error": "not found"}), 404
        return jsonify(ReportGenerator(_result_from_scan(scan)).to_sarif())

    @app.route("/export/<int:scan_id>.md")
    @require_token
    def export_md(scan_id: int):
        scan = get_scan_by_id(scan_id)
        if not scan:
            return "Report not found", 404
        return Response(
            ReportGenerator(_result_from_scan(scan)).to_markdown(),
            mimetype="text/markdown",
            headers={"Content-Disposition": f"attachment; filename=WebGuard_Scan_{scan_id}.md"},
        )

    @app.route("/export/<int:scan_id>.html")
    @require_token
    def export_html(scan_id: int):
        scan = get_scan_by_id(scan_id)
        if not scan:
            return "Report not found", 404
        return Response(
            ReportGenerator(_result_from_scan(scan)).to_html(),
            mimetype="text/html",
        )

    return app


app = create_app()

if __name__ == "__main__":
    cfg = load_config()
    print(f"[*] WebGuard dashboard: http://{cfg.server_host}:{cfg.server_port}")
    app.run(host=cfg.server_host, port=cfg.server_port, debug=cfg.server_debug, use_reloader=False)
