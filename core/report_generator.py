"""
HTML Report Generator
Creates professional HTML reports for security scan results
Matches professional security scanner output format
"""

from datetime import datetime
import html

def generate_html_report(results, output_file='security_report.html'):
    """Generate a professional HTML report matching screenshot design"""
    
    target_url = results['target_url']
    scan_time = results['scan_time'].strftime('%Y-%m-%d-%H:%M:%S')
    pages_scanned = results['pages_scanned']
    risk_score = results['risk_score']
    risk_level = results['risk_level']
    findings_summary = results['findings_summary']
    category_summary = results['category_summary']
    findings = results['findings']
    
    
    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SawSap Security Report - {html.escape(target_url)}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
            background: #ffffff;
            color: #333333;
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #ffffff;
        }}
        
        .header {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px 25px;
            margin-bottom: 20px;
        }}
        
        .header h1 {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #212529;
        }}
        
        .header-meta {{
            font-size: 13px;
            color: #6c757d;
            line-height: 1.8;
        }}
        
        .header-meta div {{
            margin: 2px 0;
        }}
        
        .risk-score {{
            font-weight: 600;
            color: #dc3545;
        }}
        
        .summary-badges {{
            background: #ffffff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px 25px;
            margin-bottom: 20px;
            display: flex;
            gap: 20px;
            align-items: center;
        }}
        
        .summary-badges span {{
            font-size: 14px;
            font-weight: 600;
        }}
        
        .badge-critical {{ color: #b91c1c; font-weight: 700; }}
        .badge-high {{ color: #dc3545; }}
        .badge-medium {{ color: #fd7e14; }}
        .badge-low {{ color: #ffc107; }}
        .badge-info {{ color: #17a2b8; }}
        
        .owasp-overview {{
            background: #ffffff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px 25px;
            margin-bottom: 20px;
        }}
        
        .owasp-overview h2 {{
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #212529;
        }}
        
        .category-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
        }}
        
        .category-box {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            padding: 15px;
            text-align: center;
        }}
        
        .category-box h3 {{
            font-size: 12px;
            color: #6c757d;
            margin-bottom: 8px;
            font-weight: 500;
        }}
        
        .category-box .count {{
            font-size: 32px;
            font-weight: 700;
            color: #212529;
        }}
        
        .findings-table {{
            background: #ffffff;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .findings-header {{
            background: #f8f9fa;
            padding: 12px 20px;
            border-bottom: 2px solid #dee2e6;
            display: grid;
            grid-template-columns: 90px 160px 1fr 280px;
            gap: 15px;
            font-weight: 600;
            font-size: 13px;
            color: #495057;
        }}
        
        .finding-row {{
            padding: 15px 20px;
            border-bottom: 1px solid #e9ecef;
            display: grid;
            grid-template-columns: 90px 160px 1fr 280px;
            gap: 15px;
            align-items: start;
            font-size: 13px;
            transition: background 0.2s;
        }}
        
        .finding-row:last-child {{
            border-bottom: none;
        }}
        
        .finding-row:hover {{
            background: #f8f9fa;
        }}
        
        .severity {{
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
        }}
        
        .severity.CRITICAL {{ color: #b91c1c; font-weight: 700; }}
        .severity.HIGH {{ color: #dc3545; }}
        .severity.MEDIUM {{ color: #fd7e14; }}
        .severity.LOW {{ color: #ffc107; }}
        .severity.INFO {{ color: #17a2b8; }}
        
        .category {{
            color: #495057;
            font-weight: 500;
        }}
        
        .description {{
            color: #212529;
            line-height: 1.5;
        }}
        
        .empty-state {{
            text-align: center;
            color: #6c757d;
            grid-column: 1 / -1;
            padding: 20px;
        }}
        
        .url {{
            color: #6c757d;
            font-size: 12px;
            word-break: break-all;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 30px;
            padding: 20px;
            color: #6c757d;
            font-size: 12px;
        }}
        
        @media (max-width: 1200px) {{
            .findings-header,
            .finding-row {{
                grid-template-columns: 80px 140px 1fr 220px;
            }}
        }}
        
        @media (max-width: 900px) {{
            .findings-header,
            .finding-row {{
                grid-template-columns: 1fr;
                gap: 8px;
            }}
            
            .findings-header {{
                display: none;
            }}
            
            .finding-row {{
                padding: 20px;
            }}
            
            .severity,
            .category {{
                display: inline-block;
                margin-right: 15px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header Section -->
        <div class="header">
            <h1>Results: {html.escape(target_url)}</h1>
            <div class="header-meta">
                <div><strong>Scanned at:</strong> {scan_time}</div>
                <div><strong>Pages scanned:</strong> {pages_scanned}</div>
                <div><strong>Risk score:</strong> <span class="risk-score">{risk_score} ({risk_level})</span></div>
            </div>
        </div>
        
        <!-- Summary Badges -->
        <div class="summary-badges">
            <span class="badge-critical">CRITICAL: {findings_summary.get('CRITICAL', 0)}</span>
            <span class="badge-high">HIGH: {findings_summary['HIGH']}</span>
            <span class="badge-medium">MEDIUM: {findings_summary['MEDIUM']}</span>
            <span class="badge-low">LOW: {findings_summary['LOW']}</span>
            <span class="badge-info">INFO: {findings_summary['INFO']}</span>
        </div>
        
        <!-- OWASP Overview -->
        <div class="owasp-overview">
            <h2>OWASP-style Overview</h2>
            <div class="category-grid">
'''
    
    # Add category boxes in specific order
    category_order = [
        'Transport Security',
        'Security Headers',
        'Session / Cookies',
        'Cryptography / TLS',
        'Input / Forms',
        'Resource Security',
        'Client-side Exposure',
        'Information Disclosure',
        'Availability / Performance',
        'Discovery / Hygiene'
    ]
    
    for category in category_order:
        count = category_summary.get(category, 0)
        html_content += f'''
                <div class="category-box">
                    <h3>{html.escape(category)}</h3>
                    <div class="count">{count}</div>
                </div>
'''
    
    html_content += '''
            </div>
        </div>
        
        <!-- Findings Table -->
        <div class="findings-table">
            <div class="findings-header">
                <div>SEVERITY</div>
                <div>CATEGORY</div>
                <div>DESCRIPTION</div>
                <div>URL</div>
            </div>
'''
    
    # Add findings rows
    if not findings:
        html_content += '''
            <div class="finding-row">
                <div class="empty-state">
                    No security issues found.
                </div>
            </div>
'''
    else:
        for finding in findings:
            severity = finding['severity']
            category = finding['category']
            title = finding['title']
            description = finding['description']
            url = finding['url']
            
            html_content += f'''
            <div class="finding-row">
                <div class="severity {severity}">{severity}</div>
                <div class="category">{html.escape(category)}</div>
                <div class="description">{html.escape(title)}</div>
                <div class="url">{html.escape(url)}</div>
            </div>
'''
    
    html_content += f'''
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>SawSap Security Report | Generated {scan_time}</p>
            <p>State of the Art Web Security Analysis Platform | For authorized security testing only.</p>
        </div>
    </div>
</body>
</html>
'''
    
    # Write to file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_file

