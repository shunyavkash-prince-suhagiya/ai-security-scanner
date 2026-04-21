"""
AI Security Scanner - Main Entry Point
"""
import json
import argparse
from pathlib import Path
from datetime import datetime
import sys

from config import EXTENSIONS, PATTERNS
from report.html_generator import HTMLReportGenerator
from scanner.file_scanner import FileScanner

def main():
    parser = argparse.ArgumentParser(description='AI Security Scanner')
    parser.add_argument('path', nargs='?', default='.', help='Path to scan')
    parser.add_argument('--output', '-o', default='security_report.html', help='Output file')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--severity', choices=['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default='LOW', help='Minimum severity')
    
    args = parser.parse_args()
    
    print("🔒 AI Security Scanner")
    print("=" * 50)
    print(f"📁 Scanning: {args.path}")
    print(f"🎯 Minimum severity: {args.severity}")
    print()
    
    # Initialize scanner
    scanner = FileScanner(PATTERNS)
    scan_path = Path(args.path)
    
    if not scan_path.exists():
        print(f"❌ Path not found: {args.path}")
        sys.exit(1)
    
    # Run scan
    findings = scanner.scan_directory(scan_path, EXTENSIONS)
    
    # Filter by severity
    severity_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}
    min_level = severity_order[args.severity]
    filtered = [f for f in findings if severity_order[f.risk_level] >= min_level]
    
    # Generate output
    if args.json:
        output = {
            'scan_time': datetime.now().isoformat(),
            'scan_path': str(scan_path),
            'total_findings': len(filtered),
            'findings': [
                {
                    'type': f.type,
                    'value': f.value,
                    'file': f.file_path,
                    'line': f.line_number,
                    'risk': f.risk_level
                }
                for f in filtered
            ]
        }
        json_path = args.output.replace('.html', '.json')
        with open(json_path, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"✅ JSON report saved: {json_path}")
    else:
        # Generate HTML report
        generator = HTMLReportGenerator()
        generator.generate(filtered, str(scan_path), args.output)
    
    # Summary
    print()
    print("📊 SUMMARY")
    print("-" * 30)
    print(f"Total findings: {len(findings)}")
    print(f"After filtering: {len(filtered)}")
    
    if filtered:
        print("\n⚠️ HIGH RISK ISSUES (first 5):")
        high_risk = [f for f in filtered if f.risk_level in ['HIGH', 'CRITICAL']]
        for f in high_risk[:5]:
            print(f"  • {f.type}: {Path(f.file_path).name}:{f.line_number}")

if __name__ == "__main__":
    main()
