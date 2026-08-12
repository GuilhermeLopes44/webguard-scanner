from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from hashlib import sha256
from typing import Any
from uuid import uuid4


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        return order[self]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


@dataclass
class Finding:
    check_id: str
    title: str
    severity: str
    confidence: str
    url: str
    method: str = "GET"
    param: str | None = None
    evidence: str = ""
    remediation: str = ""
    id: str = field(default_factory=lambda: str(uuid4()))

    def evidence_hash(self) -> str:
        raw = f"{self.check_id}|{self.url}|{self.param or ''}|{self.evidence}"
        return sha256(raw.encode("utf-8")).hexdigest()[:16]

    def dedupe_key(self) -> tuple[str, str, str, str]:
        return (self.check_id, self.url, self.param or "", self.evidence_hash())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FormTarget:
    page_url: str
    action_url: str
    method: str
    inputs: list[dict[str, str]]


@dataclass
class ParamTarget:
    url: str
    params: dict[str, list[str]]


@dataclass
class CrawlResult:
    base_url: str
    visited_urls: list[str] = field(default_factory=list)
    forms: list[FormTarget] = field(default_factory=list)
    params: list[ParamTarget] = field(default_factory=list)
    seed_html: str = ""
    seed_headers: dict[str, str] = field(default_factory=dict)
    authenticated: bool = False


@dataclass
class ScanResult:
    target_url: str
    findings: list[Finding] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    pages_crawled: int = 0
    status: str = ScanStatus.DONE.value
    error: str | None = None
    authenticated: bool = False
    auth_method: str | None = None
    auth_message: str | None = None

    def highest_severity_rank(self) -> int:
        if not self.findings:
            return 0
        return max(SEVERITY_RANK.get(f.severity, 0) for f in self.findings)

    def severity_counts(self) -> dict[str, int]:
        counts = {k: 0 for k in SEVERITY_RANK}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_url": self.target_url,
            "status": self.status,
            "error": self.error,
            "pages_crawled": self.pages_crawled,
            "technologies": self.technologies,
            "authenticated": self.authenticated,
            "auth_method": self.auth_method,
            "auth_message": self.auth_message,
            "severity_counts": self.severity_counts(),
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    out: list[Finding] = []
    for finding in findings:
        key = finding.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out
