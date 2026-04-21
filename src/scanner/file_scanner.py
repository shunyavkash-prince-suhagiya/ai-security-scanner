"""
File system scanner for security auditing.
"""
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List

@dataclass
class Finding:
    """Represents a security finding"""
    type: str
    value: str
    file_path: str
    line_number: int
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    context: str
    
class FileScanner:
    """Scans files for security issues"""
    
    def __init__(self, patterns: Dict[str, Any]):
        self.patterns = patterns
        self.findings: List[Finding] = []
        
    def scan_file(self, filepath: Path) -> List[Finding]:
        """Scan a single file"""
        findings = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            return findings
        
        for line_num, line in enumerate(lines, 1):
            for pattern_name, pattern_config in self.patterns.items():
                matches = re.finditer(
                    pattern_config['regex'], 
                    line, 
                    re.IGNORECASE
                )
                for match in matches:
                    findings.append(Finding(
                        type=pattern_name,
                        value=match.group(0)[:100],  # Truncate long values
                        file_path=str(filepath),
                        line_number=line_num,
                        risk_level=pattern_config.get('risk', 'MEDIUM'),
                        context=line.strip()[:200]
                    ))
        
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
