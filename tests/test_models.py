from core.config import AppConfig, load_config
from core.models import Finding, dedupe_findings
from core.reporter import ReportGenerator
from core.models import ScanResult


def test_dedupe_findings():
    a = Finding(
        check_id="xss_reflected",
        title="x",
        severity="high",
        confidence="high",
        url="http://x",
        evidence="payload",
    )
    b = Finding(
        check_id="xss_reflected",
        title="x",
        severity="high",
        confidence="high",
        url="http://x",
        evidence="payload",
    )
    assert len(dedupe_findings([a, b])) == 1


def test_load_config_defaults():
    cfg = load_config()
    assert isinstance(cfg, AppConfig)
    assert cfg.max_pages >= 1
    assert "xss_reflected" in cfg.enabled_checks


def test_sarif_and_json_report():
    result = ScanResult(
        target_url="http://example.test",
        findings=[
            Finding(
                check_id="security_headers",
                title="Missing CSP",
                severity="medium",
                confidence="high",
                url="http://example.test",
                evidence="no CSP",
            )
        ],
    )
    rep = ReportGenerator(result)
    data = rep.to_json_dict()
    assert data["total_findings"] == 1
    sarif = rep.to_sarif()
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
