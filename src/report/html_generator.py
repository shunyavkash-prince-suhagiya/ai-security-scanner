"""
HTML Report Generator for Security Scanner
"""
from html import escape
from pathlib import Path
from datetime import datetime
from typing import List, Dict

class HTMLReportGenerator:
    """Generates HTML reports from scan findings"""
    
    def generate(self, findings: List, scan_path: str, output_file: str) -> None:
        """Generate HTML report from findings"""
        
        # Count by risk level
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in findings:
            risk = getattr(f, 'risk_level', 'MEDIUM').lower()
            if risk in counts:
                counts[risk] += 1
        
        # Build HTML
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #dc3545; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .card {{ flex: 1; padding: 20px; border-radius: 8px; color: white; text-align: center; min-width: 120px; }}
        .card.critical {{ background: #dc3545; }}
        .card.high {{ background: #fd7e14; }}
        .card.medium {{ background: #ffc107; color: #333; }}
        .card.low {{ background: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #333; color: white; }}
        .risk-critical {{ color: #dc3545; font-weight: bold; }}
        .risk-high {{ color: #fd7e14; font-weight: bold; }}
        .risk-medium {{ color: #ffc107; font-weight: bold; }}
        code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; font-family: monospace; }}
        pre {{ background: #f4f4f4; padding: 10px; overflow-x: auto; border-radius: 5px; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; text-align: center; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Scan Report</h1>
        <p>Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p>Scan path: <code>{scan_path}</code></p>
        
        <div class="summary">
            <div class="card critical">CRITICAL<br><strong>{counts['critical']}</strong></div>
            <div class="card high">HIGH<br><strong>{counts['high']}</strong></div>
            <div class="card medium">MEDIUM<br><strong>{counts['medium']}</strong></div>
        </div>
        
        <h2>⚠️ Detailed Findings</h2>
        <table>
            <thead>
                <tr><th>Risk</th><th>Type</th><th>Value</th><th>File</th><th>Line</th></tr>
            </thead>
            <tbody>
"""
        
        for f in findings[:100]:  # Limit to 100 findings
            risk = getattr(f, 'risk_level', 'MEDIUM')
            finding_type = escape(str(getattr(f, 'type', 'Unknown')))
            finding_value = escape(str(getattr(f, 'value', '')[:50]))
            finding_path = escape(str(getattr(f, 'file_path', '')))
            html += f"""
                <tr>
                    <td class="risk-{risk.lower()}">{risk}</td>
                    <td>{finding_type}</td>
                    <td><code>{finding_value}</code></td>
                    <td><small>{finding_path}</small></td>
                    <td>{getattr(f, 'line_number', 0)}</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
        
        <div class="footer">
            <p>⚠️ Remove any exposed credentials immediately. Use environment variables or a password manager.</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Save to file
        output_path = Path(output_file)
        output_path.write_text(html, encoding='utf-8')
        print(f"✅ Report saved: {output_file}")
