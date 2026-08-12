from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import Finding, ScanResult, ScanStatus

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "webguard.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0,
            progress_message TEXT,
            scan_date TEXT NOT NULL,
            finished_at TEXT,
            total_vulns INTEGER DEFAULT 0,
            pages_crawled INTEGER DEFAULT 0,
            technologies TEXT,
            error TEXT,
            vuln_details TEXT,
            authenticated INTEGER DEFAULT 0,
            auth_method TEXT,
            auth_message TEXT
        )
        """
    )
    for col, typedef in (
        ("authenticated", "INTEGER DEFAULT 0"),
        ("auth_method", "TEXT"),
        ("auth_message", "TEXT"),
    ):
        try:
            cur.execute(f"ALTER TABLE scans ADD COLUMN {col} {typedef}")
        except sqlite3.OperationalError:
            pass
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            finding_uuid TEXT,
            check_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            url TEXT,
            method TEXT,
            param TEXT,
            evidence TEXT,
            remediation TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """
    )
    conn.commit()
    conn.close()


def create_scan(target_url: str) -> int:
    conn = _connect()
    cur = conn.cursor()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    cur.execute(
        """
        INSERT INTO scans (target_url, status, progress, progress_message, scan_date, technologies, vuln_details)
        VALUES (?, ?, 0, ?, ?, '[]', '[]')
        """,
        (target_url, ScanStatus.QUEUED.value, "Queued", now),
    )
    scan_id = int(cur.lastrowid)
    conn.commit()
    conn.close()
    return scan_id


def update_scan_progress(scan_id: int, message: str, percent: int, status: str | None = None) -> None:
    conn = _connect()
    cur = conn.cursor()
    if status:
        cur.execute(
            """
            UPDATE scans SET progress=?, progress_message=?, status=? WHERE id=?
            """,
            (percent, message, status, scan_id),
        )
    else:
        cur.execute(
            """
            UPDATE scans SET progress=?, progress_message=? WHERE id=?
            """,
            (percent, message, scan_id),
        )
    conn.commit()
    conn.close()


def finalize_scan(scan_id: int, result: ScanResult) -> None:
    conn = _connect()
    cur = conn.cursor()
    finished = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    findings_json = json.dumps([f.to_dict() for f in result.findings], ensure_ascii=False)
    techs_json = json.dumps(result.technologies, ensure_ascii=False)
    cur.execute(
        """
        UPDATE scans SET
            status=?, progress=100, progress_message=?, finished_at=?,
            total_vulns=?, pages_crawled=?, technologies=?, error=?, vuln_details=?,
            authenticated=?, auth_method=?, auth_message=?
        WHERE id=?
        """,
        (
            result.status,
            "Failed" if result.status == ScanStatus.FAILED.value else "Done",
            finished,
            len(result.findings),
            result.pages_crawled,
            techs_json,
            result.error,
            findings_json,
            1 if result.authenticated else 0,
            result.auth_method,
            result.auth_message,
            scan_id,
        ),
    )
    cur.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
    for finding in result.findings:
        cur.execute(
            """
            INSERT INTO findings (
                scan_id, finding_uuid, check_id, title, severity, confidence,
                url, method, param, evidence, remediation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                finding.id,
                finding.check_id,
                finding.title,
                finding.severity,
                finding.confidence,
                finding.url,
                finding.method,
                finding.param,
                finding.evidence,
                finding.remediation,
            ),
        )
    conn.commit()
    conn.close()


def get_all_scans() -> list[dict[str, Any]]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, target_url, status, progress, progress_message, scan_date, finished_at,
               total_vulns, pages_crawled, technologies, error, vuln_details,
               authenticated, auth_method, auth_message
        FROM scans ORDER BY id DESC
        """
    )
    rows = cur.fetchall()
    conn.close()
    return [_scan_row_to_dict(row) for row in rows]


def get_scan_by_id(scan_id: int) -> dict[str, Any] | None:
    conn = _connect()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, target_url, status, progress, progress_message, scan_date, finished_at,
               total_vulns, pages_crawled, technologies, error, vuln_details,
               authenticated, auth_method, auth_message
        FROM scans WHERE id=?
        """,
        (scan_id,),
    )
    row = cur.fetchone()
    if row is None:
        conn.close()
        return None
    data = _scan_row_to_dict(row)
    cur.execute(
        """
        SELECT finding_uuid, check_id, title, severity, confidence, url, method, param, evidence, remediation
        FROM findings WHERE scan_id=? ORDER BY id ASC
        """,
        (scan_id,),
    )
    findings_rows = cur.fetchall()
    conn.close()
    if findings_rows:
        data["findings"] = [
            {
                "id": r["finding_uuid"],
                "check_id": r["check_id"],
                "title": r["title"],
                "severity": r["severity"],
                "confidence": r["confidence"],
                "url": r["url"],
                "method": r["method"],
                "param": r["param"],
                "evidence": r["evidence"],
                "remediation": r["remediation"],
            }
            for r in findings_rows
        ]
    return data


def _scan_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    techs = json.loads(row["technologies"] or "[]")
    details = json.loads(row["vuln_details"] or "[]")
    keys = row.keys()
    return {
        "id": row["id"],
        "target": row["target_url"],
        "target_url": row["target_url"],
        "status": row["status"],
        "progress": row["progress"],
        "progress_message": row["progress_message"],
        "date": row["scan_date"],
        "finished_at": row["finished_at"],
        "total": row["total_vulns"] or 0,
        "pages_crawled": row["pages_crawled"] or 0,
        "techs": techs,
        "technologies": techs,
        "error": row["error"],
        "details": details,
        "findings": details,
        "authenticated": bool(row["authenticated"]) if "authenticated" in keys else False,
        "auth_method": row["auth_method"] if "auth_method" in keys else None,
        "auth_message": row["auth_message"] if "auth_message" in keys else None,
    }


def findings_as_models(scan: dict[str, Any]) -> list[Finding]:
    out: list[Finding] = []
    for item in scan.get("findings") or []:
        out.append(
            Finding(
                id=item.get("id") or "",
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


def fail_running_scans(message: str = "Cancelado pelo operador") -> int:
    """Mark all running/queued scans as failed (e.g. after server restart)."""
    conn = _connect()
    cur = conn.cursor()
    finished = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    cur.execute(
        """
        UPDATE scans SET status=?, progress_message=?, finished_at=?, error=?
        WHERE status IN (?, ?)
        """,
        (
            ScanStatus.FAILED.value,
            message,
            finished,
            message,
            ScanStatus.QUEUED.value,
            ScanStatus.RUNNING.value,
        ),
    )
    count = cur.rowcount
    conn.commit()
    conn.close()
    return count
