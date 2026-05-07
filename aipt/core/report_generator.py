import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import logging

from jinja2 import Environment, FileSystemLoader, BaseLoader
from .models import ScanResult, Vulnerability, Severity
from .config import ReportConfig


class ReportGenerator:
    def __init__(self, config: ReportConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)

    def generate(self, result: ScanResult) -> Dict[str, str]:
        generated_files = {}

        for fmt in self.config.formats:
            try:
                if fmt == "json":
                    path = self._generate_json(result)
                    generated_files["json"] = path
                elif fmt == "html":
                    path = self._generate_html(result)
                    generated_files["html"] = path
                elif fmt == "csv":
                    path = self._generate_csv(result)
                    generated_files["csv"] = path
                elif fmt == "sarif":
                    path = self._generate_sarif(result)
                    generated_files["sarif"] = path
                elif fmt == "xml":
                    path = self._generate_xml(result)
                    generated_files["xml"] = path
            except Exception as e:
                self.logger.error(f"Failed to generate {fmt} report: {e}")

        return generated_files

    def _generate_json(self, result: ScanResult) -> str:
        filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.config.output_dir, filename)

        report_data = result.to_dict()

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)

        self.logger.info(f"JSON report saved: {filepath}")
        return filepath

    def _generate_html(self, result: ScanResult) -> str:
        filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.config.output_dir, filename)

        html_content = self._render_html_template(result)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

        self.logger.info(f"HTML report saved: {filepath}")
        return filepath

    def _render_html_template(self, result: ScanResult) -> str:
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {{ result.target }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header .meta { opacity: 0.9; }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h3 { font-size: 0.9em; color: #666; margin-bottom: 10px; text-transform: uppercase; }
        .card .value { font-size: 2em; font-weight: bold; color: #333; }
        .severity-CRITICAL { color: #dc3545; }
        .severity-HIGH { color: #fd7e14; }
        .severity-MEDIUM { color: #ffc107; }
        .severity-LOW { color: #17a2b8; }
        .severity-INFO { color: #6c757d; }
        .vulnerability-list { background: white; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .vuln-item {
            padding: 20px;
            border-bottom: 1px solid #eee;
            transition: background 0.2s;
        }
        .vuln-item:hover { background: #f8f9fa; }
        .vuln-item:last-child { border-bottom: none; }
        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .vuln-title { font-size: 1.2em; font-weight: 600; }
        .vuln-severity {
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-CRITICAL { background: #dc3545; color: white; }
        .badge-HIGH { background: #fd7e14; color: white; }
        .badge-MEDIUM { background: #ffc107; color: #333; }
        .badge-LOW { background: #17a2b8; color: white; }
        .badge-INFO { background: #6c757d; color: white; }
        .vuln-details { color: #666; font-size: 0.95em; }
        .vuln-url { color: #667eea; word-break: break-all; }
        .vuln-evidence {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            overflow-x: auto;
        }
        .vuln-remediation {
            background: #d4edda;
            padding: 15px;
            border-radius: 5px;
            margin-top: 10px;
            border-left: 4px solid #28a745;
        }
        .stats-chart {
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .footer {
            text-align: center;
            padding: 30px;
            color: #666;
            font-size: 0.9em;
        }
        .risk-score {
            font-size: 3em;
            font-weight: bold;
            text-align: center;
        }
        .risk-critical { color: #dc3545; }
        .risk-high { color: #fd7e14; }
        .risk-medium { color: #ffc107; }
        .risk-low { color: #17a2b8; }
        .tabs { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab {
            padding: 10px 20px;
            background: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
        }
        .tab.active { background: #667eea; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Assessment Report</h1>
            <div class="meta">
                <p>Target: <strong>{{ result.target }}</strong></p>
                <p>Scan Date: {{ result.start_time.strftime('%Y-%m-%d %H:%M:%S') }}</p>
                <p>Duration: {{ "%.2f"|format(result.duration) }} seconds</p>
            </div>
        </div>

        <div class="summary-cards">
            <div class="card">
                <h3>Total Risk Score</h3>
                <div class="risk-score {% if result.total_risk_score > 50 %}risk-critical{% elif result.total_risk_score > 30 %}risk-high{% elif result.total_risk_score > 15 %}risk-medium{% else %}risk-low{% endif %}">
                    {{ "%.1f"|format(result.total_risk_score) }}
                </div>
            </div>
            <div class="card">
                <h3>URLs Discovered</h3>
                <div class="value">{{ result.urls_discovered }}</div>
            </div>
            <div class="card">
                <h3>Forms Found</h3>
                <div class="value">{{ result.forms_discovered }}</div>
            </div>
            <div class="card">
                <h3>Vulnerabilities</h3>
                <div class="value severity-CRITICAL">{{ result.severity_summary.CRITICAL + result.severity_summary.HIGH + result.severity_summary.MEDIUM + result.severity_summary.LOW }}</div>
            </div>
        </div>

        <div class="stats-chart">
            <h2>Severity Distribution</h2>
            <div style="display: flex; gap: 20px; margin-top: 15px;">
                <div style="flex: 1; text-align: center;">
                    <div class="severity-CRITICAL" style="font-size: 2em; font-weight: bold;">{{ result.severity_summary.CRITICAL }}</div>
                    <div>Critical</div>
                </div>
                <div style="flex: 1; text-align: center;">
                    <div class="severity-HIGH" style="font-size: 2em; font-weight: bold;">{{ result.severity_summary.HIGH }}</div>
                    <div>High</div>
                </div>
                <div style="flex: 1; text-align: center;">
                    <div class="severity-MEDIUM" style="font-size: 2em; font-weight: bold;">{{ result.severity_summary.MEDIUM }}</div>
                    <div>Medium</div>
                </div>
                <div style="flex: 1; text-align: center;">
                    <div class="severity-LOW" style="font-size: 2em; font-weight: bold;">{{ result.severity_summary.LOW }}</div>
                    <div>Low</div>
                </div>
                <div style="flex: 1; text-align: center;">
                    <div class="severity-INFO" style="font-size: 2em; font-weight: bold;">{{ result.severity_summary.INFO }}</div>
                    <div>Info</div>
                </div>
            </div>
        </div>

        <h2 style="margin-bottom: 20px;">Vulnerability Details</h2>
        <div class="vulnerability-list">
            {% for vuln in result.vulnerabilities|sort(attribute='risk_score', reverse=true) %}
            <div class="vuln-item">
                <div class="vuln-header">
                    <div class="vuln-title">{{ vuln.title }}</div>
                    <span class="vuln-severity badge-{{ vuln.severity.value }}">{{ vuln.severity.value }}</span>
                </div>
                <div class="vuln-details">
                    <p><strong>Type:</strong> {{ vuln.type.value }}</p>
                    <p><strong>URL:</strong> <span class="vuln-url">{{ vuln.url }}</span></p>
                    {% if vuln.parameter %}
                    <p><strong>Parameter:</strong> {{ vuln.parameter }}</p>
                    {% endif %}
                    <p><strong>Description:</strong> {{ vuln.description }}</p>
                    {% if vuln.cwe_id %}
                    <p><strong>CWE:</strong> {{ vuln.cwe_id }}</p>
                    {% endif %}
                    {% if vuln.cvss_score %}
                    <p><strong>CVSS Score:</strong> {{ vuln.cvss_score }}</p>
                    {% endif %}
                </div>
                {% if vuln.evidence and vuln.evidence.context %}
                <div class="vuln-evidence">
                    <strong>Evidence:</strong><br>
                    {{ vuln.evidence.context }}
                </div>
                {% endif %}
                {% if vuln.remediation %}
                <div class="vuln-remediation">
                    <strong>Remediation:</strong><br>
                    {{ vuln.remediation }}
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </div>

        <div class="footer">
            <p>Generated by AiPT Pro - AI-Enhanced Penetration Testing Platform</p>
            <p>This report contains confidential security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>
        """

        env = Environment(loader=BaseLoader())
        template = env.from_string(template_str)
        return template.render(result=result)

    def _generate_csv(self, result: ScanResult) -> str:
        import csv
        filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join(self.config.output_dir, filename)

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'ID', 'Type', 'Severity', 'Title', 'URL', 'Parameter',
                'Payload', 'CWE', 'CVSS', 'AI Detected', 'Description'
            ])

            for vuln in result.vulnerabilities:
                writer.writerow([
                    vuln.id,
                    vuln.type.value,
                    vuln.severity.value,
                    vuln.title,
                    vuln.url,
                    vuln.parameter,
                    vuln.payload[:200] if vuln.payload else '',
                    vuln.cwe_id or '',
                    vuln.cvss_score or '',
                    'Yes' if vuln.ai_detected else 'No',
                    vuln.description[:500]
                ])

        return filepath

    def _generate_sarif(self, result: ScanResult) -> str:
        filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sarif"
        filepath = os.path.join(self.config.output_dir, filename)

        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AiPT Pro",
                        "version": "2.0.0",
                        "informationUri": "https://aipt.security"
                    }
                },
                "results": []
            }]
        }

        for vuln in result.vulnerabilities:
            sarif_data["runs"][0]["results"].append({
                "ruleId": vuln.cwe_id or vuln.type.value,
                "level": self._severity_to_sarif_level(vuln.severity),
                "message": {"text": vuln.description},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": vuln.url}
                    }
                }]
            })

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2)

        return filepath

    def _severity_to_sarif_level(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping.get(severity, "warning")

    def _generate_xml(self, result: ScanResult) -> str:
        from xml.etree.ElementTree import Element, SubElement, tostring
        from xml.dom import minidom

        filename = f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml"
        filepath = os.path.join(self.config.output_dir, filename)

        root = Element("scan")
        SubElement(root, "target").text = result.target
        SubElement(root, "timestamp").text = result.start_time.isoformat()
        SubElement(root, "duration").text = str(result.duration)

        vulns = SubElement(root, "vulnerabilities")
        for vuln in result.vulnerabilities:
            v = SubElement(vulns, "vulnerability")
            SubElement(v, "id").text = vuln.id
            SubElement(v, "type").text = vuln.type.value
            SubElement(v, "severity").text = vuln.severity.value
            SubElement(v, "title").text = vuln.title
            SubElement(v, "url").text = vuln.url
            SubElement(v, "description").text = vuln.description

        xml_str = minidom.parseString(tostring(root)).toprettyxml(indent="  ")

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(xml_str)

        return filepath
