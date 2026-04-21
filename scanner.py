#!/usr/bin/env python3
"""
Simple Security Scanner - Find emails, passwords, and API keys in your files
"""

import re
import os
import json
from html import escape
from pathlib import Path
from datetime import datetime

class SecurityScanner:
    def __init__(self):
        self.patterns = {
            '📧 Email': {
                'regex': r'\b[\w\.-]+@[\w\.-]+\.\w{2,}\b',
                'risk': 'MEDIUM',
                'icon': '📧'
            },
            '🔑 Password': {
                'regex': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\'\s]{4,})["\']',
                'risk': 'HIGH',
                'icon': '🔑'
            },
            '🔐 API Key': {
                'regex': r'(?i)(api[_-]?key|token|secret)\s*[=:]\s*["\']([a-zA-Z0-9_-]{16,})["\']',
                'risk': 'CRITICAL',
                'icon': '🔐'
            },
            '🔑 AWS Key': {
                'regex': r'(?i)(AKIA|ASIA)[A-Z0-9]{16}',
                'risk': 'CRITICAL',
                'icon': '🔑'
            },
            '🔗 Basic Auth URL': {
                'regex': r'https?://([^:]+):([^@]+)@',
                'risk': 'CRITICAL',
                'icon': '🔗'
            }
        }
        
        # File types to scan
        self.extensions = ['.txt', '.json', '.yml', '.yaml', '.py', '.js', '.env', '.conf', '.ini', '.xml', '.html', '.md']
    
    def scan_file(self, filepath):
        """Scan a single file for security issues"""
        findings = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return findings
        
        for line_num, line in enumerate(lines, 1):
            for name, config in self.patterns.items():
                matches = re.finditer(config['regex'], line, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        'type': name,
                        'icon': config['icon'],
                        'value': match.group(0)[:60],
                        'file': str(filepath),
                        'line': line_num,
                        'risk': config['risk']
                    })
        return findings
    
    def scan(self, path='.'):
        """Scan directory for security issues"""
        scan_path = Path(path)
        if not scan_path.exists():
            print(f"❌ Path not found: {path}")
            return []
        
        all_findings = []
        files_scanned = 0
        
        print(f"🔍 Scanning: {scan_path.absolute()}")
        print("-" * 50)
        
        if scan_path.is_file():
            candidates = [scan_path] if scan_path.suffix.lower() in self.extensions else []
        else:
            candidates = []
            for ext in self.extensions:
                candidates.extend(scan_path.rglob(f'*{ext}'))

        for filepath in candidates:
            # Skip virtual environments and caches
            if 'venv' in str(filepath) or '__pycache__' in str(filepath):
                continue
            files_scanned += 1
            if files_scanned % 50 == 0:
                print(f"📄 Scanned {files_scanned} files...")
            findings = self.scan_file(filepath)
            all_findings.extend(findings)
        
        print(f"\n✅ Scanned {files_scanned} files")
        return all_findings
    
    def generate_report(self, findings, output_file='security_report.html'):
        """Generate HTML report"""
        
        # Count by risk
        critical = sum(1 for f in findings if f['risk'] == 'CRITICAL')
        high = sum(1 for f in findings if f['risk'] == 'HIGH')
        medium = sum(1 for f in findings if f['risk'] == 'MEDIUM')
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #dc3545; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .card {{ flex: 1; padding: 20px; border-radius: 8px; color: white; text-align: center; }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #333; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #333; color: white; }}
        .risk-critical {{ color: #dc3545; font-weight: bold; }}
        .risk-high {{ color: #fd7e14; font-weight: bold; }}
        code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-family: monospace; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Scan Report</h1>
        <p>Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary">
            <div class="card critical">CRITICAL<br><strong>{critical}</strong></div>
            <div class="card high">HIGH<br><strong>{high}</strong></div>
            <div class="card medium">MEDIUM<br><strong>{medium}</strong></div>
        </div>
        
        <h2>⚠️ Findings</h2>
"""
        
        if findings:
            html += """
        <table>
            <thead>
                <tr><th>Risk</th><th>Type</th><th>Value</th><th>Location</th><th>Line</th></tr>
            </thead>
            <tbody>
"""
            for f in findings[:100]:  # Limit to 100 findings
                html += f"""
                <tr>
                    <td class="risk-{f['risk'].lower()}">{f['risk']}</td>
                    <td>{escape(f['type'])}</td>
                    <td><code>{escape(f['value'])}</code></td>
                    <td><small>{escape(Path(f['file']).name)}</small></td>
                    <td>{f['line']}</td>
                </tr>
"""
            html += """
            </tbody>
        </table>
"""
        else:
            html += "<p>🎉 No security issues found!</p>"
        
        html += f"""
        <div class="footer">
            <p>⚠️ Remove any exposed credentials immediately. Use environment variables or a password manager.</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Save report
        with open(output_file, 'w') as f:
            f.write(html)
        print(f"\n📄 Report saved: {output_file}")
        
        # Print summary to terminal
        print("\n" + "="*50)
        print("📊 SUMMARY")
        print("="*50)
        print(f"🔴 CRITICAL: {critical}")
        print(f"🟠 HIGH: {high}")
        print(f"🟡 MEDIUM: {medium}")
        
        # Show high risk items
        high_risk = [f for f in findings if f['risk'] in ['CRITICAL', 'HIGH']]
        if high_risk:
            print("\n⚠️  HIGH RISK ISSUES:")
            for f in high_risk[:10]:
                print(f"  {f['icon']} {f['type']} in {Path(f['file']).name}:{f['line']}")
        
        return critical + high

def main():
    print("""
╔══════════════════════════════════════════╗
║     🔒 AI Security Scanner               ║
║     Find exposed credentials in your code║
╚══════════════════════════════════════════╝
    """)
    
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    output = sys.argv[2] if len(sys.argv) > 2 else "security_report.html"
    
    scanner = SecurityScanner()
    findings = scanner.scan(path)
    risk_count = scanner.generate_report(findings, output)
    
    # Open report in browser if there are findings
    if findings:
        import webbrowser
        try:
            webbrowser.open(f'file://{Path(output).absolute()}')
            print(f"\n🌐 Report opened in your browser")
        except Exception as exc:
            print(f"\n⚠️ Could not open browser automatically: {exc}")
    else:
        print("\n🎉 Great! No security issues found!")

if __name__ == "__main__":
    main()
