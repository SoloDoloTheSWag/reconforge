"""
Custom Report Templates System for ReconForge
Provides flexible report generation with customizable templates
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from jinja2 import Environment, FileSystemLoader, BaseLoader, DictLoader
# Optional dependencies for advanced features
try:
    import markdown
    MARKDOWN_AVAILABLE = True
except ImportError:
    MARKDOWN_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

try:
    import pandas as pd
    import numpy as np
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
import io
import base64

from .logging import main_logger

class ReportTemplateManager:
    """Manages custom report templates for various output formats"""
    
    def __init__(self, templates_dir: str = "templates/reports"):
        self.templates_dir = Path(templates_dir)
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.custom_templates = {}
        self.load_default_templates()
    
    def load_default_templates(self):
        """Load default report templates"""
        self.custom_templates = {
            "executive_summary": {
                "name": "Executive Summary",
                "description": "High-level security assessment report for executives",
                "format": "html",
                "template": self._get_executive_template()
            },
            "technical_detailed": {
                "name": "Technical Detailed Report",
                "description": "Comprehensive technical security assessment",
                "format": "html",
                "template": self._get_technical_template()
            },
            "compliance_report": {
                "name": "Compliance Report",
                "description": "Security compliance assessment report",
                "format": "html",
                "template": self._get_compliance_template()
            },
            "vulnerability_summary": {
                "name": "Vulnerability Summary",
                "description": "Focused vulnerability assessment report",
                "format": "html",
                "template": self._get_vulnerability_template()
            },
            "trend_analysis": {
                "name": "Security Trend Analysis",
                "description": "Historical trend analysis and comparison report",
                "format": "html",
                "template": self._get_trend_template()
            }
        }
    
    def _get_executive_template(self) -> str:
        """Executive summary template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Security Summary - {{ organization_name }}</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6; 
            margin: 0; 
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 2rem;
            border-radius: 10px;
            margin-bottom: 2rem;
            text-align: center;
        }
        .risk-score {
            font-size: 3rem;
            font-weight: bold;
            margin: 1rem 0;
        }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #28a745; }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .card {
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #007bff;
        }
        .card.critical { border-left-color: #dc3545; }
        .card.high { border-left-color: #fd7e14; }
        .card.medium { border-left-color: #ffc107; }
        .card.info { border-left-color: #17a2b8; }
        .recommendations {
            background: white;
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .priority-high { color: #dc3545; font-weight: bold; }
        .priority-medium { color: #fd7e14; }
        .priority-low { color: #28a745; }
        table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background-color: #f8f9fa; font-weight: 600; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <h2>{{ organization_name }}</h2>
        <div class="risk-score risk-{{ risk_level }}">
            Risk Score: {{ risk_score }}
        </div>
        <p>Assessment Period: {{ assessment_period }}</p>
        <p>Generated: {{ generation_date }}</p>
    </div>

    <div class="summary-cards">
        <div class="card critical">
            <h3>Critical Issues</h3>
            <div style="font-size: 2rem; color: #dc3545;">{{ critical_count }}</div>
            <p>Require immediate attention</p>
        </div>
        <div class="card high">
            <h3>High Priority</h3>
            <div style="font-size: 2rem; color: #fd7e14;">{{ high_count }}</div>
            <p>Address within 7 days</p>
        </div>
        <div class="card medium">
            <h3>Medium Priority</h3>
            <div style="font-size: 2rem; color: #ffc107;">{{ medium_count }}</div>
            <p>Plan remediation</p>
        </div>
        <div class="card info">
            <h3>Total Scans</h3>
            <div style="font-size: 2rem; color: #17a2b8;">{{ total_scans }}</div>
            <p>Completed assessments</p>
        </div>
    </div>

    <div class="recommendations">
        <h2>Executive Summary</h2>
        <p>{{ executive_summary }}</p>
        
        <h3>Key Findings</h3>
        <ul>
        {% for finding in key_findings %}
            <li class="priority-{{ finding.priority }}">{{ finding.description }}</li>
        {% endfor %}
        </ul>

        <h3>Immediate Action Items</h3>
        <table>
            <thead>
                <tr>
                    <th>Priority</th>
                    <th>Issue</th>
                    <th>Impact</th>
                    <th>Recommended Action</th>
                </tr>
            </thead>
            <tbody>
            {% for action in action_items %}
                <tr>
                    <td><span class="priority-{{ action.priority }}">{{ action.priority.upper() }}</span></td>
                    <td>{{ action.issue }}</td>
                    <td>{{ action.impact }}</td>
                    <td>{{ action.action }}</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
        """
    
    def _get_technical_template(self) -> str:
        """Technical detailed report template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Technical Security Assessment - {{ target }}</title>
    <style>
        body { 
            font-family: 'Courier New', monospace;
            line-height: 1.4; 
            margin: 0; 
            padding: 20px;
            background-color: #1a1a1a;
            color: #00ff00;
        }
        .header {
            border: 2px solid #00ff00;
            padding: 1rem;
            margin-bottom: 2rem;
            background-color: #2a2a2a;
        }
        .section {
            margin-bottom: 2rem;
            border-left: 3px solid #00ff00;
            padding-left: 1rem;
        }
        .vulnerability {
            background-color: #2a2a2a;
            border: 1px solid #444;
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 5px;
        }
        .severity-critical { border-left: 4px solid #ff0000; }
        .severity-high { border-left: 4px solid #ff6600; }
        .severity-medium { border-left: 4px solid #ffff00; }
        .severity-low { border-left: 4px solid #00ff00; }
        .code {
            background-color: #000;
            border: 1px solid #444;
            padding: 0.5rem;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            white-space: pre-wrap;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            background-color: #2a2a2a;
            color: #00ff00;
        }
        th, td { 
            padding: 0.5rem; 
            border: 1px solid #444;
            text-align: left;
        }
        th { background-color: #1a1a1a; }
    </style>
</head>
<body>
    <div class="header">
        <h1>[RECONFORGE] TECHNICAL SECURITY ASSESSMENT</h1>
        <p>Target: {{ target }}</p>
        <p>Scan ID: {{ scan_id }}</p>
        <p>Start Time: {{ start_time }}</p>
        <p>Duration: {{ duration }}</p>
        <p>Scanned by: {{ scanner_info }}</p>
    </div>

    <div class="section">
        <h2>[SCOPE] Assessment Scope</h2>
        <ul>
        {% for scope_item in scope %}
            <li>{{ scope_item }}</li>
        {% endfor %}
        </ul>
    </div>

    <div class="section">
        <h2>[DISCOVERY] Subdomain Enumeration</h2>
        <p>Total Subdomains Found: {{ subdomain_count }}</p>
        <table>
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Technology</th>
                    <th>Source</th>
                </tr>
            </thead>
            <tbody>
            {% for subdomain in subdomains %}
                <tr>
                    <td>{{ subdomain.name }}</td>
                    <td>{{ subdomain.ip }}</td>
                    <td>{{ subdomain.status }}</td>
                    <td>{{ subdomain.tech }}</td>
                    <td>{{ subdomain.source }}</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>[VULNS] Vulnerability Assessment</h2>
        <p>Total Vulnerabilities: {{ vulnerability_count }}</p>
        
        {% for vuln in vulnerabilities %}
        <div class="vulnerability severity-{{ vuln.severity }}">
            <h3>[{{ vuln.severity.upper() }}] {{ vuln.title }}</h3>
            <p><strong>Target:</strong> {{ vuln.target }}</p>
            <p><strong>Type:</strong> {{ vuln.type }}</p>
            <p><strong>CVSS Score:</strong> {{ vuln.cvss_score or 'N/A' }}</p>
            <p><strong>Description:</strong></p>
            <div class="code">{{ vuln.description }}</div>
            
            {% if vuln.payload %}
            <p><strong>Payload:</strong></p>
            <div class="code">{{ vuln.payload }}</div>
            {% endif %}
            
            {% if vuln.response %}
            <p><strong>Response:</strong></p>
            <div class="code">{{ vuln.response[:500] }}{% if vuln.response|length > 500 %}...{% endif %}</div>
            {% endif %}
            
            <p><strong>Remediation:</strong> {{ vuln.remediation or 'Review and validate finding' }}</p>
        </div>
        {% endfor %}
    </div>

    <div class="section">
        <h2>[SERVICES] Port & Service Analysis</h2>
        <table>
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>State</th>
                </tr>
            </thead>
            <tbody>
            {% for service in services %}
                <tr>
                    <td>{{ service.host }}</td>
                    <td>{{ service.port }}</td>
                    <td>{{ service.protocol }}</td>
                    <td>{{ service.service_name }}</td>
                    <td>{{ service.version or 'Unknown' }}</td>
                    <td>{{ service.state }}</td>
                </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>[PENTESTS] Penetration Testing Results</h2>
        {% for pentest in pentests %}
        <div class="vulnerability">
            <h3>[{{ pentest.success and 'SUCCESS' or 'FAILED' }}] {{ pentest.test_type }}</h3>
            <p><strong>Target:</strong> {{ pentest.target }}</p>
            <p><strong>Command:</strong></p>
            <div class="code">{{ pentest.command }}</div>
            <p><strong>Output:</strong></p>
            <div class="code">{{ pentest.output }}</div>
            {% if pentest.recommendations %}
            <p><strong>Recommendations:</strong> {{ pentest.recommendations }}</p>
            {% endif %}
        </div>
        {% endfor %}
    </div>

    <div class="section">
        <h2>[END] Assessment Complete</h2>
        <p>Report generated: {{ generation_date }}</p>
        <p>Total issues found: {{ total_issues }}</p>
        <p>ReconForge v{{ version }}</p>
    </div>
</body>
</html>
        """
    
    def _get_compliance_template(self) -> str:
        """Compliance report template"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Compliance Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif;
            line-height: 1.6; 
            margin: 0; 
            padding: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background: #003366;
            color: white;
            padding: 2rem;
            text-align: center;
            margin-bottom: 2rem;
        }
        .framework-section {
            background: white;
            margin-bottom: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .framework-header {
            background: #0066cc;
            color: white;
            padding: 1rem;
            font-weight: bold;
            font-size: 1.2rem;
        }
        .framework-content {
            padding: 1.5rem;
        }
        .score-bar {
            width: 100%;
            height: 20px;
            background: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        .score-fill {
            height: 100%;
            transition: width 0.3s ease;
        }
        .score-excellent { background: #28a745; }
        .score-good { background: #ffc107; }
        .score-needs-improvement { background: #fd7e14; }
        .score-poor { background: #dc3545; }
        .controls-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
        }
        .controls-table th,
        .controls-table td {
            padding: 0.75rem;
            border: 1px solid #dee2e6;
            text-align: left;
        }
        .controls-table th {
            background: #f8f9fa;
            font-weight: 600;
        }
        .status-pass { color: #28a745; font-weight: bold; }
        .status-fail { color: #dc3545; font-weight: bold; }
        .status-partial { color: #ffc107; font-weight: bold; }
        .recommendations {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 1rem;
            margin-top: 1rem;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Compliance Assessment</h1>
        <p>Organization: {{ organization_name }}</p>
        <p>Assessment Date: {{ assessment_date }}</p>
        <p>Overall Compliance Score: {{ overall_score }}%</p>
    </div>

    {% for framework in frameworks %}
    <div class="framework-section">
        <div class="framework-header">
            {{ framework.name }} Compliance
        </div>
        <div class="framework-content">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <span><strong>Compliance Score: {{ framework.score }}%</strong></span>
                <span>Target: {{ framework.target }}%</span>
            </div>
            
            <div class="score-bar">
                <div class="score-fill score-{{ framework.score_class }}" 
                     style="width: {{ framework.score }}%;"></div>
            </div>

            <p>{{ framework.description }}</p>

            <h4>Control Assessment</h4>
            <table class="controls-table">
                <thead>
                    <tr>
                        <th>Control ID</th>
                        <th>Control Description</th>
                        <th>Status</th>
                        <th>Evidence</th>
                        <th>Gaps</th>
                    </tr>
                </thead>
                <tbody>
                {% for control in framework.controls %}
                    <tr>
                        <td>{{ control.id }}</td>
                        <td>{{ control.description }}</td>
                        <td class="status-{{ control.status }}">{{ control.status.upper() }}</td>
                        <td>{{ control.evidence }}</td>
                        <td>{{ control.gaps or 'None identified' }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>

            <div class="recommendations">
                <h5>Recommendations</h5>
                <ul>
                {% for recommendation in framework.recommendations %}
                    <li>{{ recommendation }}</li>
                {% endfor %}
                </ul>
            </div>
        </div>
    </div>
    {% endfor %}

    <div style="background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1);">
        <h2>Executive Summary</h2>
        <p>{{ executive_summary }}</p>
        
        <h3>Priority Actions</h3>
        <ol>
        {% for action in priority_actions %}
            <li><strong>{{ action.title }}:</strong> {{ action.description }}</li>
        {% endfor %}
        </ol>
    </div>
</body>
</html>
        """
    
    def _get_vulnerability_template(self) -> str:
        """Vulnerability summary template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .vuln-critical { border-left: 5px solid #d32f2f; background: #ffebee; }
        .vuln-high { border-left: 5px solid #f57c00; background: #fff3e0; }
        .vuln-medium { border-left: 5px solid #fbc02d; background: #fffde7; }
        .vuln-low { border-left: 5px solid #388e3c; background: #e8f5e8; }
        .vuln-item { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .cvss-score { float: right; padding: 5px 10px; border-radius: 15px; color: white; font-weight: bold; }
        .cvss-critical { background: #d32f2f; }
        .cvss-high { background: #f57c00; }
        .cvss-medium { background: #fbc02d; }
        .cvss-low { background: #388e3c; }
    </style>
</head>
<body>
    <h1>Vulnerability Assessment Report</h1>
    <p><strong>Target:</strong> {{ target }}</p>
    <p><strong>Scan Date:</strong> {{ scan_date }}</p>
    <p><strong>Total Vulnerabilities:</strong> {{ total_vulns }}</p>
    
    <div style="margin: 20px 0;">
        <strong>Severity Distribution:</strong>
        Critical: {{ severity_counts.critical }} | 
        High: {{ severity_counts.high }} | 
        Medium: {{ severity_counts.medium }} | 
        Low: {{ severity_counts.low }}
    </div>

    {% for vuln in vulnerabilities %}
    <div class="vuln-item vuln-{{ vuln.severity }}">
        <h3>{{ vuln.title }}
            {% if vuln.cvss_score %}
            <span class="cvss-score cvss-{{ vuln.severity }}">CVSS: {{ vuln.cvss_score }}</span>
            {% endif %}
        </h3>
        <p><strong>URL:</strong> {{ vuln.url or vuln.target }}</p>
        <p><strong>Type:</strong> {{ vuln.vulnerability_type }}</p>
        <p><strong>Description:</strong> {{ vuln.description }}</p>
        {% if vuln.payload %}
        <p><strong>Proof of Concept:</strong></p>
        <code style="background: #f5f5f5; padding: 10px; display: block;">{{ vuln.payload }}</code>
        {% endif %}
        <p><strong>Impact:</strong> {{ vuln.impact or 'See description for impact details' }}</p>
        <p><strong>Remediation:</strong> {{ vuln.remediation or 'Validate and fix the identified vulnerability' }}</p>
    </div>
    {% endfor %}
</body>
</html>
        """
    
    def _get_trend_template(self) -> str:
        """Trend analysis template"""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>Security Trend Analysis</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .chart-container { width: 100%; height: 400px; margin: 20px 0; }
        .trend-up { color: #d32f2f; }
        .trend-down { color: #388e3c; }
        .trend-stable { color: #1976d2; }
        .metric-card { 
            display: inline-block; 
            background: #f5f5f5; 
            padding: 15px; 
            margin: 10px; 
            border-radius: 8px; 
            min-width: 200px;
        }
    </style>
</head>
<body>
    <h1>Security Trend Analysis</h1>
    <p><strong>Analysis Period:</strong> {{ period }}</p>
    <p><strong>Generated:</strong> {{ generation_date }}</p>

    <h2>Key Metrics</h2>
    {% for metric in key_metrics %}
    <div class="metric-card">
        <h3>{{ metric.name }}</h3>
        <div style="font-size: 24px; font-weight: bold;">{{ metric.current_value }}</div>
        <div class="trend-{{ metric.trend }}">{{ metric.change }}</div>
    </div>
    {% endfor %}

    <h2>Vulnerability Trends</h2>
    <div class="chart-container">
        <canvas id="vulnTrendChart"></canvas>
    </div>

    <h2>Scan Activity</h2>
    <div class="chart-container">
        <canvas id="scanActivityChart"></canvas>
    </div>

    <script>
        // Vulnerability trend chart
        new Chart(document.getElementById('vulnTrendChart'), {
            type: 'line',
            data: {{ vulnerability_chart_data | tojsonfilter }},
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });

        // Scan activity chart
        new Chart(document.getElementById('scanActivityChart'), {
            type: 'bar',
            data: {{ scan_activity_data | tojsonfilter }},
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    </script>
</body>
</html>
        """
    
    def create_custom_template(self, template_id: str, name: str, description: str, 
                             template_content: str, format_type: str = "html") -> bool:
        """Create a new custom template"""
        try:
            self.custom_templates[template_id] = {
                "name": name,
                "description": description,
                "format": format_type,
                "template": template_content,
                "created_at": datetime.now().isoformat(),
                "custom": True
            }
            
            # Save to file
            template_file = self.templates_dir / f"{template_id}.json"
            with open(template_file, 'w') as f:
                json.dump(self.custom_templates[template_id], f, indent=2)
            
            main_logger.info(f"Created custom template: {template_id}")
            return True
            
        except Exception as e:
            main_logger.error(f"Error creating custom template: {e}")
            return False
    
    def generate_report(self, template_id: str, data: Dict[str, Any], 
                       output_format: str = "html") -> Optional[str]:
        """Generate a report using specified template"""
        try:
            if template_id not in self.custom_templates:
                raise ValueError(f"Template {template_id} not found")
            
            template_info = self.custom_templates[template_id]
            template_content = template_info["template"]
            
            # Create Jinja2 environment
            env = Environment(
                loader=DictLoader({template_id: template_content}),
                autoescape=True
            )
            
            # Add custom filters
            env.filters['tojsonfilter'] = json.dumps
            
            # Render template
            template = env.get_template(template_id)
            rendered_html = template.render(**data)
            
            if output_format.lower() == "pdf":
                return self._convert_to_pdf(rendered_html)
            else:
                return rendered_html
                
        except Exception as e:
            main_logger.error(f"Error generating report: {e}")
            return None
    
    def _convert_to_pdf(self, html_content: str) -> str:
        """Convert HTML content to PDF"""
        try:
            import pdfkit
            
            # Configure options
            options = {
                'page-size': 'A4',
                'margin-top': '0.75in',
                'margin-right': '0.75in',
                'margin-bottom': '0.75in',
                'margin-left': '0.75in',
                'encoding': "UTF-8",
                'no-outline': None,
                'enable-local-file-access': None
            }
            
            # Generate PDF
            pdf_content = pdfkit.from_string(html_content, False, options=options)
            return base64.b64encode(pdf_content).decode('utf-8')
            
        except ImportError:
            main_logger.warning("pdfkit not available - PDF conversion disabled")
            return None
        except Exception as e:
            main_logger.error(f"Error converting to PDF: {e}")
            return None
    
    def list_templates(self) -> List[Dict[str, Any]]:
        """List all available templates"""
        return [
            {
                "id": tid,
                "name": template["name"],
                "description": template["description"],
                "format": template["format"],
                "custom": template.get("custom", False)
            }
            for tid, template in self.custom_templates.items()
        ]
    
    def get_template_preview(self, template_id: str) -> Optional[str]:
        """Get template preview/schema"""
        if template_id not in self.custom_templates:
            return None
        
        template_info = self.custom_templates[template_id]
        
        # Extract template variables for preview
        from jinja2 import Environment, meta
        env = Environment()
        ast = env.parse(template_info["template"])
        variables = meta.find_undeclared_variables(ast)
        
        return {
            "template_id": template_id,
            "name": template_info["name"],
            "description": template_info["description"],
            "format": template_info["format"],
            "required_variables": list(variables),
            "preview": template_info["template"][:500] + "..." if len(template_info["template"]) > 500 else template_info["template"]
        }

# Global template manager instance
report_templates = ReportTemplateManager()