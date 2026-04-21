"""Celery tasks for background scan processing."""
from __future__ import annotations

import json
import os
from pathlib import Path

from celery import Celery

# Reuse the existing scanning engine.
from src.config import EXTENSIONS, PATTERNS
from src.report.html_generator import HTMLReportGenerator
from src.scanner.file_scanner import FileScanner


celery_app = Celery(
    "scanner_worker",
    broker=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/1"),
)


@celery_app.task(name="scanner.process_scan")
def process_scan(scan_id: str, target_path: str) -> dict:
    scanner = FileScanner(PATTERNS)
    findings = scanner.scan_directory(Path(target_path), EXTENSIONS)

    reports_dir = Path(os.getenv("REPORTS_DIR", "/tmp/security-scanner/reports"))
    reports_dir.mkdir(parents=True, exist_ok=True)
    html_path = reports_dir / f"{scan_id}.html"
    json_path = reports_dir / f"{scan_id}.json"

    HTMLReportGenerator().generate(findings, target_path, str(html_path))
    json_path.write_text(
        json.dumps(
            [
                {
                    "type": finding.type,
                    "risk_level": finding.risk_level,
                    "risk_score": finding.risk_score,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "detector": finding.detector,
                }
                for finding in findings
            ],
            indent=2,
        ),
        encoding="utf-8",
    )

    return {
        "scan_id": scan_id,
        "report_html": str(html_path),
        "report_json": str(json_path),
        "total_findings": len(findings),
    }
