import zipfile
from pathlib import Path

from ai import AIAnalyzer
from config import EXTENSIONS, PATTERNS
from scanner.file_scanner import FileScanner
from web_app import _scan_uploaded_path


def test_scan_single_file_finds_secret(tmp_path):
    sample = tmp_path / "secrets.env"
    sample.write_text('API_KEY="abcdefghijklmnop"\n', encoding="utf-8")

    scanner = FileScanner(PATTERNS)
    findings = scanner.scan_directory(sample, EXTENSIONS)

    assert len(findings) == 1
    assert findings[0].type == "API Key"
    assert findings[0].risk_level == "CRITICAL"


def test_scan_directory_filters_extensions(tmp_path):
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    supported = scan_root / "config.env"
    ignored = scan_root / "binary.bin"

    supported.write_text('password="hunter2"\n', encoding="utf-8")
    ignored.write_text('password="should-not-match"\n', encoding="utf-8")

    scanner = FileScanner(PATTERNS)
    findings = scanner.scan_directory(scan_root, EXTENSIONS)

    assert len(findings) == 1
    assert Path(findings[0].file_path).name == "config.env"


def test_scan_uploaded_zip_finds_nested_secret(tmp_path):
    project_root = tmp_path / "project"
    nested = project_root / "service"
    nested.mkdir(parents=True)
    secret_file = nested / ".env"
    secret_file.write_text('token="abcdefghijklmnop"\n', encoding="utf-8")

    zip_path = tmp_path / "project.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.write(secret_file, arcname="project/service/.env")

    findings = _scan_uploaded_path(zip_path)

    assert len(findings) == 1
    assert findings[0].type == "API Key"
    assert findings[0].file_path.endswith("project/service/.env")


def test_ai_analyzer_detects_obfuscated_secret_assignment(tmp_path):
    suspect_file = tmp_path / "service.py"
    suspect_file.write_text(
        'client_secret_blob = "QWxhZGRpbjpvcGVuIHNlc2FtZTEyMzQ1Njc4OTA="\n',
        encoding="utf-8",
    )

    scanner = FileScanner(PATTERNS)
    findings = scanner.scan_directory(suspect_file, EXTENSIONS)

    assert any(f.type == "AI Suspicious Secret" for f in findings)
    ai_finding = next(f for f in findings if f.type == "AI Suspicious Secret")
    assert ai_finding.detector == "ai"
    assert ai_finding.risk_score >= 61


def test_ai_scoring_reduces_test_fixture_severity():
    analyzer = AIAnalyzer()
    score, classification, evidence = analyzer.score_finding(
        match_type="API Key",
        file_path="tests/fixtures/sample.env",
        context='token = "dummy-token-value"',
        value="dummy-token-value",
        frequency=1,
        file_content='token = "dummy-token-value"\n# sample fixture\n',
    )

    assert score < 81
    assert classification in {"MEDIUM", "HIGH"}
    assert any("test-or-mock-file" == item for item in evidence)
