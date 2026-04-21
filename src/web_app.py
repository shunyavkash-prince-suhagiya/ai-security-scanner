"""
Minimal Flask web interface for the security scanner.
"""
from collections import Counter
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import zipfile

from flask import Flask, render_template_string, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

try:
    from config import EXTENSIONS, PATTERNS
    from scanner.file_scanner import FileScanner
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from src.config import EXTENSIONS, PATTERNS
    from src.scanner.file_scanner import FileScanner

app = Flask(__name__)
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "50"))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
ARCHIVE_EXTENSIONS = {".zip"}

TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Security Scanner</title>
  <style>
    :root {
      --bg: #f4efe6;
      --panel: #fffaf2;
      --ink: #1f2937;
      --accent: #9a3412;
      --critical: #b91c1c;
      --high: #ea580c;
      --medium: #ca8a04;
      --low: #15803d;
      --border: #e5d4b8;
    }
    body {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      background: radial-gradient(circle at top, #fff7ed, var(--bg));
      color: var(--ink);
    }
    .wrap {
      max-width: 980px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 18px 40px rgba(31, 41, 55, 0.08);
    }
    h1 {
      margin: 0 0 10px;
      font-size: 2.2rem;
    }
    p {
      line-height: 1.55;
    }
    form {
      display: grid;
      gap: 14px;
      margin-top: 18px;
    }
    input[type="file"] {
      border: 1px dashed var(--border);
      padding: 16px;
      border-radius: 12px;
      background: white;
    }
    button {
      width: fit-content;
      padding: 12px 18px;
      border: 0;
      border-radius: 999px;
      background: var(--accent);
      color: white;
      font-size: 1rem;
      cursor: pointer;
    }
    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 12px;
      margin: 20px 0;
    }
    .card {
      border-radius: 14px;
      padding: 16px;
      color: white;
      font-weight: 700;
    }
    .critical { background: var(--critical); }
    .high { background: var(--high); }
    .medium { background: var(--medium); }
    .low { background: var(--low); }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 12px;
      font-size: 0.95rem;
    }
    th, td {
      text-align: left;
      padding: 10px 8px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    .note {
      color: #7c2d12;
      font-size: 0.95rem;
    }
    .subtle {
      color: #6b7280;
      font-size: 0.95rem;
    }
    code {
      background: rgba(154, 52, 18, 0.08);
      padding: 2px 6px;
      border-radius: 6px;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="panel">
      <h1>AI Security Scanner</h1>
      <p>Upload a supported file or a <code>.zip</code> of your project and the scanner will look for emails, hardcoded passwords, API keys, AWS keys, and Basic Auth URLs.</p>
      <p class="note">Supported scan targets: {{ extensions|join(", ") }} and .zip archives</p>
      <p class="subtle">For a full project scan on the web app, zip the folder first and upload the zip file.</p>
      <form method="post" enctype="multipart/form-data">
        <input type="file" name="scan_file" required>
        <button type="submit">Scan Upload</button>
      </form>

      {% if error %}
      <p class="note">{{ error }}</p>
      {% endif %}

      {% if filename %}
      <h2>Results for <code>{{ filename }}</code></h2>
      <p class="subtle">Scanned {{ findings|length }} matching findings.</p>
      <div class="cards">
        <div class="card critical">CRITICAL<br>{{ counts["CRITICAL"] }}</div>
        <div class="card high">HIGH<br>{{ counts["HIGH"] }}</div>
        <div class="card medium">MEDIUM<br>{{ counts["MEDIUM"] }}</div>
        <div class="card low">LOW<br>{{ counts["LOW"] }}</div>
      </div>

      {% if findings %}
      <table>
        <thead>
          <tr>
            <th>Risk</th>
            <th>Score</th>
            <th>Detector</th>
            <th>Type</th>
            <th>Value</th>
            <th>File</th>
            <th>Line</th>
          </tr>
        </thead>
        <tbody>
          {% for finding in findings %}
          <tr>
            <td>{{ finding.risk_level }}</td>
            <td>{{ finding.risk_score }}</td>
            <td>{{ finding.detector }}</td>
            <td>{{ finding.type }}</td>
            <td><code>{{ finding.value }}</code></td>
            <td><code>{{ finding.file_path }}</code></td>
            <td>{{ finding.line_number }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p>No sensitive data patterns matched.</p>
      {% endif %}
      {% endif %}
    </div>
  </div>
</body>
</html>
"""


def _allowed_file(filename: str) -> bool:
    suffix = Path(filename).suffix.lower()
    return suffix in set(EXTENSIONS) or suffix in ARCHIVE_EXTENSIONS


def _safe_extract_zip(zip_path: Path, extract_root: Path) -> Path:
    """Extract a zip archive safely and return the directory to scan."""
    archive_root = extract_root / "uploaded_zip"
    archive_root.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            member_path = Path(member.filename)
            if member_path.is_absolute():
                raise ValueError("Zip archive contains absolute paths.")
            if ".." in member_path.parts:
                raise ValueError("Zip archive contains unsafe paths.")
        archive.extractall(archive_root)

    return archive_root


def _scan_uploaded_path(upload_path: Path):
    """Scan a single uploaded file or an extracted zip directory."""
    scanner = FileScanner(PATTERNS)

    if upload_path.suffix.lower() in ARCHIVE_EXTENSIONS:
        extract_root = upload_path.parent / "extracted"
        scan_root = _safe_extract_zip(upload_path, extract_root)
    else:
        scan_root = upload_path

    findings = scanner.scan_directory(scan_root, EXTENSIONS)

    # Shorten displayed paths for zip uploads so results are easier to read.
    normalized_findings = []
    for finding in findings:
        file_path = Path(finding.file_path)
        try:
            finding.file_path = str(file_path.relative_to(scan_root))
        except ValueError:
            finding.file_path = file_path.name
        normalized_findings.append(finding)

    return normalized_findings


def _render_home(error=None, filename=None, findings=None):
    findings = findings or []
    grouped = Counter(finding.risk_level for finding in findings)
    counts = {
        "CRITICAL": grouped.get("CRITICAL", 0),
        "HIGH": grouped.get("HIGH", 0),
        "MEDIUM": grouped.get("MEDIUM", 0),
        "LOW": grouped.get("LOW", 0),
    }
    return render_template_string(
        TEMPLATE,
        extensions=EXTENSIONS,
        error=error,
        filename=filename,
        counts=counts,
        findings=findings,
    )


@app.get("/")
def index():
    return _render_home()


@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(_error):
    return _render_home(
        error=(
            f"Upload too large. The current limit is {MAX_UPLOAD_MB} MB. "
            "Zip the folder more tightly or upload a smaller archive."
        )
    ), 413


@app.post("/")
def scan_upload():
    uploaded_file = request.files.get("scan_file")
    if uploaded_file is None or not uploaded_file.filename:
        return _render_home(error="Choose a file to scan first.")

    if not _allowed_file(uploaded_file.filename):
        return _render_home(error="That file type is not supported yet.")

    with TemporaryDirectory() as temp_dir:
        safe_name = secure_filename(uploaded_file.filename)
        temp_path = Path(temp_dir) / safe_name
        uploaded_file.save(temp_path)
        try:
            findings = _scan_uploaded_path(temp_path)
        except zipfile.BadZipFile:
            return _render_home(error="That zip file could not be opened.")
        except ValueError as exc:
            return _render_home(error=str(exc))

    return _render_home(filename=uploaded_file.filename, findings=findings)


@app.get("/healthz")
def healthcheck():
    return {"status": "ok"}


def main():
    app.run(host="0.0.0.0", port=5000, debug=True)


if __name__ == "__main__":
    main()
