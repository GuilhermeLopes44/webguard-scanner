from __future__ import annotations

import argparse
import os

from core import __version__
from core.auth import TargetAuth
from core.config import load_config
from core.engine import ScanEngine
from core.logging_setup import setup_logging, get_logger
from core.models import SEVERITY_RANK, ScanStatus
from core.reporter import ReportGenerator
from db.database import create_scan, finalize_scan, init_db, update_scan_progress

log = get_logger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webguard",
        description="WebGuard — local DAST scanner for authorized testing",
    )
    parser.add_argument("--version", action="version", version=f"WebGuard {__version__}")
    parser.add_argument("--config", help="Path to webguard.yaml")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Run a synchronous scan")
    scan.add_argument("-u", "--url", required=True, help="Target URL (authorized only)")
    scan.add_argument("--max-pages", type=int)
    scan.add_argument("--max-depth", type=int)
    scan.add_argument("--timeout", type=float)
    scan.add_argument("--json-out", default="webguard_report.json")
    scan.add_argument("--sarif-out", default="")
    scan.add_argument("--md-out", default="webguard_executive.md", help="Executive Markdown report")
    scan.add_argument("--html-out", default="webguard_executive.html", help="Executive HTML report")
    scan.add_argument("--no-db", action="store_true", help="Do not persist to SQLite")
    scan.add_argument("--login-url", help="Form login URL (absolute or path)")
    scan.add_argument("--username", help="Login username")
    scan.add_argument("--password", help="Login password")
    scan.add_argument("--username-field", default="username")
    scan.add_argument("--password-field", default="password")
    scan.add_argument("--success-marker", help="Substring expected in login response")
    scan.add_argument("--cookie", help='Raw Cookie header, e.g. "session=abc"')
    scan.add_argument("--auth-header", help='Authorization header value, e.g. "Bearer ..."')
    scan.add_argument(
        "--seed-path",
        action="append",
        default=[],
        help="Extra path to crawl after auth (repeatable)",
    )

    serve = sub.add_parser("serve", help="Start local dashboard")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--debug", action="store_true")

    parser.add_argument("-u", "--url", help=argparse.SUPPRESS)
    return parser


def _auth_from_args(args: argparse.Namespace, cfg_auth: TargetAuth) -> TargetAuth:
    auth = TargetAuth(
        login_url=args.login_url or cfg_auth.login_url,
        username=args.username or cfg_auth.username or os.environ.get("WEBGUARD_TARGET_USER"),
        password=args.password or cfg_auth.password or os.environ.get("WEBGUARD_TARGET_PASS"),
        username_field=args.username_field or cfg_auth.username_field,
        password_field=args.password_field or cfg_auth.password_field,
        extra_fields=dict(cfg_auth.extra_fields),
        cookie=args.cookie or cfg_auth.cookie or os.environ.get("WEBGUARD_TARGET_COOKIE"),
        authorization=args.auth_header
        or cfg_auth.authorization
        or os.environ.get("WEBGUARD_TARGET_AUTH_HEADER"),
        success_marker=args.success_marker or cfg_auth.success_marker,
        seed_paths=list(args.seed_path or []) or list(cfg_auth.seed_paths),
    )
    return auth


def cmd_scan(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.max_pages is not None:
        cfg.max_pages = args.max_pages
    if args.max_depth is not None:
        cfg.max_depth = args.max_depth
    if args.timeout is not None:
        cfg.timeout = args.timeout

    auth = _auth_from_args(args, cfg.target_auth)
    cfg.target_auth = auth

    init_db()
    scan_id = None
    if not args.no_db:
        scan_id = create_scan(args.url)
        update_scan_progress(scan_id, "Starting", 1, status=ScanStatus.RUNNING.value)

    def on_progress(message: str, percent: int) -> None:
        print(f"[{percent:3d}%] {message}")
        if scan_id is not None:
            update_scan_progress(scan_id, message, percent, status=ScanStatus.RUNNING.value)

    engine = ScanEngine(cfg)
    result = engine.run(args.url, progress_cb=on_progress, auth=auth)

    if scan_id is not None:
        finalize_scan(scan_id, result)

    reporter = ReportGenerator(result)
    path = reporter.write_json(args.json_out)
    print(f"[+] JSON report: {path.resolve()}")
    if args.md_out:
        md = reporter.write_markdown(args.md_out)
        print(f"[+] Executive Markdown: {md.resolve()}")
    if args.html_out:
        html_path = reporter.write_html(args.html_out)
        print(f"[+] Executive HTML: {html_path.resolve()}")
    if args.sarif_out:
        sarif_path = reporter.write_sarif(args.sarif_out)
        print(f"[+] SARIF report: {sarif_path.resolve()}")

    print(
        f"[+] Status: {result.status} | auth={result.authenticated} "
        f"| findings: {len(result.findings)} | pages: {result.pages_crawled}"
    )
    if result.error:
        print(f"[!] Error: {result.error}")
        return 2

    if result.highest_severity_rank() >= SEVERITY_RANK["high"]:
        return 1
    return 0 if result.status == ScanStatus.DONE.value else 2


def cmd_serve(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    if args.host:
        cfg.server_host = args.host
    if args.port:
        cfg.server_port = args.port
    if args.debug:
        cfg.server_debug = True

    from web.app import create_app

    app = create_app(cfg)
    print(f"[*] WebGuard dashboard: http://{cfg.server_host}:{cfg.server_port}")
    if not os.environ.get("WEBGUARD_TOKEN"):
        print("[!] WEBGUARD_TOKEN is not set — scan endpoints are open on localhost.")
    app.run(host=cfg.server_host, port=cfg.server_port, debug=cfg.server_debug, use_reloader=False)
    return 0


def main(argv: list[str] | None = None) -> None:
    setup_logging()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None and args.url:
        args.command = "scan"
        args.max_pages = None
        args.max_depth = None
        args.timeout = None
        args.json_out = "webguard_report.json"
        args.sarif_out = ""
        args.md_out = "webguard_executive.md"
        args.html_out = "webguard_executive.html"
        args.no_db = False
        args.login_url = None
        args.username = None
        args.password = None
        args.username_field = "username"
        args.password_field = "password"
        args.success_marker = None
        args.cookie = None
        args.auth_header = None
        args.seed_path = []

    if args.command == "scan":
        raise SystemExit(cmd_scan(args))
    if args.command == "serve":
        raise SystemExit(cmd_serve(args))

    parser.print_help()
    raise SystemExit(0)


if __name__ == "__main__":
    main()
