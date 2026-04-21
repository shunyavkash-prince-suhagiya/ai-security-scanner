"""
Lightweight AI-style analyzer for contextual secret detection.

This module uses low-cost heuristics and statistical signals instead of
GPU-backed models so it can run on CPU within a small memory budget.
"""
from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Dict, List, Tuple


RISK_BANDS = {
    "LOW": (0, 30),
    "MEDIUM": (31, 60),
    "HIGH": (61, 80),
    "CRITICAL": (81, 100),
}


class AIAnalyzer:
    """Context-aware analyzer that augments regex findings with scoring."""

    _SUSPICIOUS_VARIABLES = (
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "credential",
        "private_key",
        "access_key",
        "client_secret",
        "bearer",
        "session",
        "cookie",
    )
    _PUBLIC_MARKERS = ("public", "static", "templates", "frontend", "web", "client")
    _TEST_MARKERS = ("test", "tests", "mock", "dummy", "sample", "fixture", "example")
    _SAFE_HINTS = (
        "example",
        "dummy",
        "sample",
        "mock",
        "fake",
        "test",
        "todo",
        "docs",
        "readme",
        "os.getenv",
        "process.env",
        "placeholder",
    )
    _OBFUSCATED_VALUE = re.compile(r"(?i)([A-Za-z0-9+/=_-]{20,})")
    _ASSIGNMENT = re.compile(
        r"""(?ix)
        (?P<name>[a-z_][a-z0-9_\-]{2,40})
        \s*[:=]\s*
        ["']?
        (?P<value>[A-Za-z0-9+/=_\.-]{8,})
        ["']?
        """
    )

    def analyze_context(self, file_content: str) -> Dict[str, int]:
        """Extract low-cost semantic signals from a file body."""
        lowered = file_content.lower()
        lines = file_content.splitlines()
        suspicious_name_hits = sum(
            lowered.count(token.replace("_", "")) + lowered.count(token)
            for token in self._SUSPICIOUS_VARIABLES[:8]
        )
        test_markers = sum(lowered.count(marker) for marker in self._TEST_MARKERS)
        safe_hints = sum(lowered.count(marker) for marker in self._SAFE_HINTS)
        encoded_runs = sum(1 for line in lines if self._looks_encoded(line))
        comment_secret_refs = sum(
            1
            for line in lines
            if any(prefix in line.strip() for prefix in ("#", "//", "/*"))
            and any(term in line.lower() for term in self._SUSPICIOUS_VARIABLES[:6])
        )
        return {
            "suspicious_name_hits": suspicious_name_hits,
            "test_markers": test_markers,
            "safe_hints": safe_hints,
            "encoded_runs": encoded_runs,
            "comment_secret_refs": comment_secret_refs,
            "line_count": len(lines),
        }

    def score_finding(
        self,
        match_type: str,
        file_path: str,
        context: str,
        value: str,
        frequency: int,
        file_content: str,
    ) -> Tuple[int, str, List[str]]:
        """Score a finding from 0-100 and return classification and evidence."""
        path = Path(file_path)
        extension = path.suffix.lower()
        signals = self.analyze_context(file_content)
        context_lower = context.lower()
        path_parts = {part.lower() for part in path.parts}

        base_scores = {
            "Email Address": 24,
            "Hardcoded Password": 66,
            "API Key": 78,
            "AWS Key": 90,
            "Basic Auth URL": 84,
            "AI Suspicious Secret": 62,
        }
        score = base_scores.get(match_type, 45)
        evidence: List[str] = [f"base={score}"]

        if extension in {".env", ".ini", ".cfg", ".conf", ".yaml", ".yml"}:
            score += 10
            evidence.append("sensitive-config-file")
        if extension in {".html", ".js", ".md", ".xml"} or path_parts.intersection(self._PUBLIC_MARKERS):
            score += 12
            evidence.append("public-facing-file")

        if any(term in context_lower for term in self._SUSPICIOUS_VARIABLES):
            score += 12
            evidence.append("suspicious-variable-name")

        if self._looks_encoded(value):
            score += 10
            evidence.append("obfuscated-or-encoded-value")

        entropy = self._shannon_entropy(value)
        if entropy >= 3.5 and len(value) >= 16:
            score += 8
            evidence.append("high-entropy-value")

        if signals["comment_secret_refs"] > 0:
            score += 4
            evidence.append("comment-discusses-secrets")

        if signals["encoded_runs"] > 1:
            score += 4
            evidence.append("multiple-encoded-lines")

        if frequency > 1:
            frequency_boost = min(14, 4 * (frequency - 1))
            score += frequency_boost
            evidence.append(f"repeated-{frequency}x")

        if path_parts.intersection(self._TEST_MARKERS):
            score -= 20
            evidence.append("test-or-mock-file")

        if any(hint in context_lower for hint in self._SAFE_HINTS):
            score -= 16
            evidence.append("mock-or-placeholder-context")

        if match_type == "Email Address" and "contact" in context_lower:
            score -= 8
            evidence.append("likely-contact-address")

        score = max(0, min(100, score))
        return score, self.classify_risk(score), evidence

    def detect_ai_findings(self, file_path: str, file_content: str) -> List[Dict[str, object]]:
        """Find suspicious assignments that regex rules may miss."""
        findings: List[Dict[str, object]] = []
        lines = file_content.splitlines()

        for line_number, line in enumerate(lines, 1):
            if self._looks_benign(line):
                continue

            match = self._ASSIGNMENT.search(line)
            if not match:
                continue

            variable_name = match.group("name")
            value = match.group("value")
            normalized_name = variable_name.lower().replace("-", "_")

            suspicious_name = any(term in normalized_name for term in self._SUSPICIOUS_VARIABLES)
            if not suspicious_name:
                continue

            entropy = self._shannon_entropy(value)
            encoded = self._looks_encoded(value)
            if len(value) < 12 or (entropy < 3.1 and not encoded):
                continue

            score, classification, evidence = self.score_finding(
                match_type="AI Suspicious Secret",
                file_path=file_path,
                context=line,
                value=value,
                frequency=1,
                file_content=file_content,
            )
            findings.append(
                {
                    "type": "AI Suspicious Secret",
                    "value": value[:100],
                    "file_path": file_path,
                    "line_number": line_number,
                    "risk_level": classification,
                    "risk_score": score,
                    "context": line.strip()[:200],
                    "detector": "ai",
                    "evidence": evidence + [
                        f"variable={variable_name}",
                        f"entropy={entropy:.2f}",
                    ],
                }
            )

        return findings

    @staticmethod
    def classify_risk(score: int) -> str:
        for level, (lower, upper) in RISK_BANDS.items():
            if lower <= score <= upper:
                return level
        return "CRITICAL"

    def _looks_benign(self, line: str) -> bool:
        lowered = line.lower()
        return any(hint in lowered for hint in self._SAFE_HINTS)

    def _looks_encoded(self, value: str) -> bool:
        candidate = value.strip().strip("\"'")
        if len(candidate) < 20:
            return False
        if not self._OBFUSCATED_VALUE.fullmatch(candidate):
            return False
        has_mixed_case = any(ch.islower() for ch in candidate) and any(ch.isupper() for ch in candidate)
        has_digits = any(ch.isdigit() for ch in candidate)
        return has_mixed_case or has_digits or "=" in candidate or "/" in candidate or "+" in candidate

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: Dict[str, int] = {}
        for char in value:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0.0
        length = len(value)
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return entropy
