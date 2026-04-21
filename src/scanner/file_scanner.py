"""
File system scanner for security auditing.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List

try:
    from ai import AIAnalyzer
except ModuleNotFoundError:  # pragma: no cover - package import fallback
    from src.ai import AIAnalyzer

@dataclass
class Finding:
    """Represents a security finding"""
    type: str
    value: str
    file_path: str
    line_number: int
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    context: str
    risk_score: int = 0
    detector: str = "regex"
    evidence: List[str] = field(default_factory=list)
    
class FileScanner:
    """Scans files for security issues"""
    
    def __init__(self, patterns: Dict[str, Any]):
        self.patterns = patterns
        self.findings: List[Finding] = []
        self.ai_analyzer = AIAnalyzer()
        
    def scan_file(self, filepath: Path) -> List[Finding]:
        """Scan a single file"""
        findings = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            return findings

        lines = content.splitlines()
        regex_hits_per_type: Dict[str, int] = {}
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_config in self.patterns.items():
                matches = re.finditer(
                    pattern_config['regex'], 
                    line, 
                    re.IGNORECASE
                )
                for match in matches:
                    regex_hits_per_type[pattern_name] = regex_hits_per_type.get(pattern_name, 0) + 1
                    findings.append(Finding(
                        type=pattern_name,
                        value=match.group(0)[:100],  # Truncate long values
                        file_path=str(filepath),
                        line_number=line_num,
                        risk_level=pattern_config.get('risk', 'MEDIUM'),
                        context=line.strip()[:200],
                    ))

        for finding in findings:
            frequency = regex_hits_per_type.get(finding.type, 1)
            score, classification, evidence = self.ai_analyzer.score_finding(
                match_type=finding.type,
                file_path=finding.file_path,
                context=finding.context,
                value=finding.value,
                frequency=frequency,
                file_content=content,
            )
            finding.risk_score = score
            finding.risk_level = classification
            finding.evidence = evidence

        for ai_finding in self.ai_analyzer.detect_ai_findings(str(filepath), content):
            findings.append(
                Finding(
                    type=str(ai_finding["type"]),
                    value=str(ai_finding["value"]),
                    file_path=str(ai_finding["file_path"]),
                    line_number=int(ai_finding["line_number"]),
                    risk_level=str(ai_finding["risk_level"]),
                    context=str(ai_finding["context"]),
                    risk_score=int(ai_finding["risk_score"]),
                    detector=str(ai_finding["detector"]),
                    evidence=list(ai_finding["evidence"]),
                )
            )
        
        return findings

    def _iter_files(self, path: Path, extensions: Iterable[str]) -> Iterable[Path]:
        """Yield supported files from a file or directory path."""
        normalized_extensions = {ext.lower() for ext in extensions}

        if path.is_file():
            if path.suffix.lower() in normalized_extensions:
                yield path
            return

        for filepath in path.rglob("*"):
            if not filepath.is_file():
                continue
            if filepath.suffix.lower() not in normalized_extensions:
                continue
            yield filepath
    
    def scan_directory(self, directory: Path, extensions: List[str]) -> List[Finding]:
        """Scan all matching files from a directory or a single file path."""
        all_findings = []
        files_scanned = 0
        
        for filepath in self._iter_files(directory, extensions):
            files_scanned += 1
            if files_scanned % 100 == 0:
                print(f"Scanned {files_scanned} files...")
            findings = self.scan_file(filepath)
            all_findings.extend(findings)
        
        print(f"✅ Scanned {files_scanned} files")
        return all_findings
