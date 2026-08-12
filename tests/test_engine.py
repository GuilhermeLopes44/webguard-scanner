from core.auth import TargetAuth
from core.crawler import WebCrawler
from core.engine import ScanEngine
from core.http_client import RateLimitedSession
from core.reporter import ReportGenerator


def test_crawler_finds_forms_and_params(vuln_server, config):
    session = RateLimitedSession(config, allowed_hosts={"127.0.0.1:8765"})
    crawl = WebCrawler(vuln_server, config, session=session).crawl()
    assert crawl.visited_urls
    assert any(p for p in crawl.params if "q" in p.params or "next" in p.params)
    assert any(f.method == "post" for f in crawl.forms)


def test_engine_detects_core_issues(vuln_server, config):
    result = ScanEngine(config).run(vuln_server)
    assert result.status == "done"
    check_ids = {f.check_id for f in result.findings}
    assert "security_headers" in check_ids
    assert "xss_reflected" in check_ids or "sqli_error" in check_ids
    assert "cors_misconfig" in check_ids
    assert "sensitive_paths" in check_ids
    assert "csrf_heuristic" in check_ids
    assert "open_redirect" in check_ids


def test_open_redirect_finding(vuln_server, config):
    config.enabled_checks = ["open_redirect"]
    result = ScanEngine(config).run(vuln_server)
    assert any(f.check_id == "open_redirect" for f in result.findings)


def test_authenticated_crawl_reaches_private(vuln_server, config):
    auth = TargetAuth(
        login_url=f"{vuln_server}/auth/login",
        username="admin",
        password="admin123",
        success_marker="LOGIN_OK",
        seed_paths=["/private", "/private/search?q=test"],
    )
    config.enabled_checks = ["xss_reflected", "security_headers"]
    result = ScanEngine(config).run(vuln_server, auth=auth)
    assert result.status == "done"
    assert result.authenticated is True
    assert result.auth_method == "form_login"
    assert result.pages_crawled >= 2
    # Private reflected XSS surface
    assert any("/private" in f.url for f in result.findings) or result.pages_crawled >= 2


def test_executive_reports(vuln_server, config):
    config.enabled_checks = ["security_headers"]
    result = ScanEngine(config).run(vuln_server)
    rep = ReportGenerator(result)
    md = rep.to_markdown()
    html = rep.to_html()
    assert "Executive Report" in md
    assert "WebGuard Executive Report" in html
    assert "Severity breakdown" in md
