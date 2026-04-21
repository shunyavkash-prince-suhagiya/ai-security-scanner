import zipfile
from pathlib import Path

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
