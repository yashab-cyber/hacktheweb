"""
Report Generator - Creates comprehensive security reports
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
import markdown


class ReportGenerator:
    """Generate security scan reports in various formats"""
    
    def __init__(self, config):
        """Initialize report generator"""
        self.config = config
        self.report_dir = Path(__file__).parent.parent.parent / 'reports'
        self.report_dir.mkdir(exist_ok=True)
        
    def generate(self, results: Dict[str, Any], format: str = 'html') -> str:
        """Generate report in specified format"""
        
        if format == 'json':
            return self._generate_json(results)
        elif format == 'html':
            return self._generate_html(results)
        elif format == 'markdown':
            return self._generate_markdown(results)
        elif format == 'pdf':
            return self._generate_pdf(results)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_json(self, results: Dict[str, Any]) -> str:
        """Generate JSON report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"report_{timestamp}.json"
        filepath = self.report_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        return str(filepath)
    
    def _generate_html(self, results: Dict[str, Any]) -> str:
        """Generate HTML report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"report_{timestamp}.html"
        filepath = self.report_dir / filename
        
        html_content = self._create_html_report(results)
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def _generate_markdown(self, results: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"report_{timestamp}.md"
        filepath = self.report_dir / filename
        
        md_content = self._create_markdown_report(results)
        
        with open(filepath, 'w') as f:
            f.write(md_content)
        
        return str(filepath)
    
    def _generate_pdf(self, results: Dict[str, Any]) -> str:
        """Generate PDF report"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{timestamp}.pdf"
            filepath = self.report_dir / filename
            
            doc = SimpleDocTemplate(str(filepath), pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30,
                alignment=1  # Center
            )
            story.append(Paragraph("HackTheWeb Security Report", title_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Target info
            target = results.get('target', 'N/A')
            story.append(Paragraph(f"<b>Target:</b> {target}", styles['Normal']))
            story.append(Paragraph(f"<b>Scan Date:</b> {results.get('start_time', 'N/A')}", styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
            
            # Summary statistics
            stats = results.get('statistics', {})
            story.append(Paragraph("<b>Summary</b>", styles['Heading2']))
            
            summary_data = [
                ['Total Vulnerabilities', str(stats.get('total_vulnerabilities', 0))],
                ['Critical', str(stats.get('by_severity', {}).get('critical', 0))],
                ['High', str(stats.get('by_severity', {}).get('high', 0))],
                ['Medium', str(stats.get('by_severity', {}).get('medium', 0))],
                ['Low', str(stats.get('by_severity', {}).get('low', 0))],
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.5*inch))
            
            # Vulnerabilities
            story.append(Paragraph("<b>Vulnerabilities Found</b>", styles['Heading2']))
            story.append(Spacer(1, 0.2*inch))
            
            for i, vuln in enumerate(results.get('vulnerabilities', []), 1):
                story.append(Paragraph(f"<b>{i}. {vuln.get('type', 'Unknown').upper()}</b>", styles['Heading3']))
                story.append(Paragraph(f"<b>Severity:</b> {vuln.get('severity', 'N/A')}", styles['Normal']))
                story.append(Paragraph(f"<b>URL:</b> {vuln.get('url', 'N/A')}", styles['Normal']))
                story.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'N/A')}", styles['Normal']))
                story.append(Paragraph(f"<b>Remediation:</b> {vuln.get('remediation', 'N/A')}", styles['Normal']))
                story.append(Spacer(1, 0.2*inch))
            
            doc.build(story)
            return str(filepath)
            
        except ImportError:
            print("[!] ReportLab not installed. Cannot generate PDF. Generating HTML instead.")
            return self._generate_html(results)
    
    def _create_html_report(self, results: Dict[str, Any]) -> str:
        """Create HTML report content"""
        target = results.get('target', 'N/A')
        stats = results.get('statistics', {})
        vulnerabilities = results.get('vulnerabilities', [])
        
        # Severity colors
        severity_colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8',
            'info': '#6c757d',
        }
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HackTheWeb Security Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .info-box {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        
        .stat-label {{
            color: #666;
            text-transform: uppercase;
            font-size: 0.9em;
        }}
        
        .vulnerability {{
            background: white;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            border-left: 5px solid #ccc;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .vulnerability.critical {{
            border-left-color: #dc3545;
        }}
        
        .vulnerability.high {{
            border-left-color: #fd7e14;
        }}
        
        .vulnerability.medium {{
            border-left-color: #ffc107;
        }}
        
        .vulnerability.low {{
            border-left-color: #17a2b8;
        }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        
        .vuln-title {{
            font-size: 1.3em;
            font-weight: bold;
        }}
        
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            text-transform: uppercase;
            font-size: 0.85em;
        }}
        
        .vuln-details {{
            margin: 10px 0;
        }}
        
        .detail-row {{
            margin: 8px 0;
        }}
        
        .detail-label {{
            font-weight: bold;
            color: #555;
        }}
        
        .code-block {{
            background: #f4f4f4;
            padding: 10px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        footer {{
            text-align: center;
            padding: 20px;
            color: #666;
            margin-top: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 HackTheWeb Security Report</h1>
            <div class="subtitle">Automated Web Application Security Assessment</div>
        </header>
        
        <div class="info-box">
            <h2>Scan Information</h2>
            <div class="detail-row"><span class="detail-label">Target:</span> {target}</div>
            <div class="detail-row"><span class="detail-label">Scan Started:</span> {results.get('start_time', 'N/A')}</div>
            <div class="detail-row"><span class="detail-label">Scan Completed:</span> {results.get('end_time', 'N/A')}</div>
            <div class="detail-row"><span class="detail-label">Duration:</span> {stats.get('scan_duration', 0):.2f} seconds</div>
        </div>
        
        <h2 style="margin: 30px 0 20px 0;">Statistics Overview</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Vulnerabilities</div>
                <div class="stat-number">{stats.get('total_vulnerabilities', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical</div>
                <div class="stat-number" style="color: {severity_colors['critical']}">{stats.get('by_severity', {}).get('critical', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High</div>
                <div class="stat-number" style="color: {severity_colors['high']}">{stats.get('by_severity', {}).get('high', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium</div>
                <div class="stat-number" style="color: {severity_colors['medium']}">{stats.get('by_severity', {}).get('medium', 0)}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Low</div>
                <div class="stat-number" style="color: {severity_colors['low']}">{stats.get('by_severity', {}).get('low', 0)}</div>
            </div>
        </div>
        
        <h2 style="margin: 30px 0 20px 0;">Vulnerabilities Found ({len(vulnerabilities)})</h2>
"""
        
        # Add vulnerabilities
        for i, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'info')
            color = severity_colors.get(severity, '#6c757d')
            
            html += f"""
        <div class="vulnerability {severity}">
            <div class="vuln-header">
                <div class="vuln-title">{i}. {vuln.get('type', 'Unknown').upper()}</div>
                <span class="severity-badge" style="background-color: {color}">{severity}</span>
            </div>
            <div class="vuln-details">
                <div class="detail-row"><span class="detail-label">URL:</span> {vuln.get('url', 'N/A')}</div>
                <div class="detail-row"><span class="detail-label">Method:</span> {vuln.get('method', 'N/A')}</div>
                <div class="detail-row"><span class="detail-label">Parameter:</span> {vuln.get('parameter', 'N/A')}</div>
                <div class="detail-row"><span class="detail-label">Description:</span> {vuln.get('description', 'N/A')}</div>
                <div class="detail-row"><span class="detail-label">CWE:</span> {vuln.get('cwe', 'N/A')}</div>
                <div class="detail-row"><span class="detail-label">OWASP:</span> {vuln.get('owasp', 'N/A')}</div>
                {f'<div class="detail-row"><span class="detail-label">Payload:</span><div class="code-block">{vuln.get("payload", "N/A")}</div></div>' if 'payload' in vuln else ''}
                <div class="detail-row"><span class="detail-label">Remediation:</span> {vuln.get('remediation', 'N/A')}</div>
            </div>
        </div>
"""
        
        html += """
        <footer>
            <p>Generated by HackTheWeb v1.0 - AI-Powered Web Security Scanner</p>
            <p>⚠️ This report contains sensitive security information. Handle with care.</p>
        </footer>
    </div>
</body>
</html>
"""
        
        return html
    
    def _create_markdown_report(self, results: Dict[str, Any]) -> str:
        """Create Markdown report content"""
        target = results.get('target', 'N/A')
        stats = results.get('statistics', {})
        vulnerabilities = results.get('vulnerabilities', [])
        
        md = f"""# HackTheWeb Security Report

## Scan Information

- **Target:** {target}
- **Scan Started:** {results.get('start_time', 'N/A')}
- **Scan Completed:** {results.get('end_time', 'N/A')}
- **Duration:** {stats.get('scan_duration', 0):.2f} seconds

## Statistics Overview

| Metric | Count |
|--------|-------|
| Total Vulnerabilities | {stats.get('total_vulnerabilities', 0)} |
| Critical | {stats.get('by_severity', {}).get('critical', 0)} |
| High | {stats.get('by_severity', {}).get('high', 0)} |
| Medium | {stats.get('by_severity', {}).get('medium', 0)} |
| Low | {stats.get('by_severity', {}).get('low', 0)} |

## Vulnerabilities Found

"""
        
        for i, vuln in enumerate(vulnerabilities, 1):
            md += f"""
### {i}. {vuln.get('type', 'Unknown').upper()} - {vuln.get('severity', 'Unknown').upper()}

- **URL:** {vuln.get('url', 'N/A')}
- **Method:** {vuln.get('method', 'N/A')}
- **Parameter:** {vuln.get('parameter', 'N/A')}
- **Description:** {vuln.get('description', 'N/A')}
- **CWE:** {vuln.get('cwe', 'N/A')}
- **OWASP:** {vuln.get('owasp', 'N/A')}
"""
            
            if 'payload' in vuln:
                md += f"""
- **Payload:**
  ```
  {vuln.get('payload', 'N/A')}
  ```
"""
            
            md += f"""
- **Remediation:** {vuln.get('remediation', 'N/A')}

---

"""
        
        md += """
---
*Generated by HackTheWeb v1.0 - AI-Powered Web Security Scanner*

⚠️ This report contains sensitive security information. Handle with care.
"""
        
        return md
