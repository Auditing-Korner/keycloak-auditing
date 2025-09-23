import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from ..core.config import AuditorConfig
from ..cve.database import get_cves_for_version


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Keycloak Security Audit Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 2.5em; }
        .header .meta { margin-top: 10px; opacity: 0.9; }
        .content { padding: 30px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
        .summary-card { background: #f8f9fa; padding: 20px; border-radius: 6px; border-left: 4px solid #007bff; }
        .summary-card h3 { margin: 0 0 10px 0; color: #333; }
        .summary-card .number { font-size: 2em; font-weight: bold; color: #007bff; }
        .chart-container { margin: 30px 0; }
        .findings-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .findings-table th, .findings-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .findings-table th { background: #f8f9fa; font-weight: 600; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #fd7e14; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        .severity-info { color: #17a2b8; font-weight: bold; }
        .cve-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .cve-table th, .cve-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .cve-table th { background: #f8f9fa; font-weight: 600; }
        .section { margin: 40px 0; }
        .section h2 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .json-block { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; font-family: monospace; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Keycloak Security Audit Report</h1>
            <div class="meta">
                <strong>Target:</strong> {{ base_url }}<br>
                <strong>Realm:</strong> {{ realm }}<br>
                <strong>Version:</strong> {{ version or 'Unknown' }}<br>
                <strong>Generated:</strong> {{ timestamp }}
            </div>
        </div>
        
        <div class="content">
            <div class="summary-grid">
                <div class="summary-card">
                    <h3>Total Findings</h3>
                    <div class="number">{{ total_findings }}</div>
                </div>
                <div class="summary-card">
                    <h3>Critical</h3>
                    <div class="number severity-critical">{{ severity_counts.critical or 0 }}</div>
                </div>
                <div class="summary-card">
                    <h3>High</h3>
                    <div class="number severity-high">{{ severity_counts.high or 0 }}</div>
                </div>
                <div class="summary-card">
                    <h3>Medium</h3>
                    <div class="number severity-medium">{{ severity_counts.medium or 0 }}</div>
                </div>
                <div class="summary-card">
                    <h3>CVEs</h3>
                    <div class="number">{{ cves|length }}</div>
                </div>
            </div>

            <div class="chart-container">
                <canvas id="severityChart" width="400" height="200"></canvas>
            </div>

            {% if cves %}
            <div class="section">
                <h2>Known Vulnerabilities (CVEs)</h2>
                <table class="cve-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Severity</th>
                            <th>CVSS</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for cve in cves %}
                        <tr>
                            <td><strong>{{ cve.cve_id }}</strong></td>
                            <td><span class="severity-{{ cve.severity }}">{{ cve.severity|upper }}</span></td>
                            <td>{{ cve.cvss }}</td>
                            <td>{{ cve.description }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% endif %}

            <div class="section">
                <h2>Top Findings</h2>
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Source</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for finding in top_findings %}
                        <tr>
                            <td><span class="severity-{{ finding.severity }}">{{ finding.severity|upper }}</span></td>
                            <td>{{ finding.title }}</td>
                            <td>{{ finding.source }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>Detailed Results</h2>
                <h3>Enumeration</h3>
                <div class="json-block">{{ enumeration_json }}</div>
                
                <h3>Audit Findings</h3>
                <div class="json-block">{{ audit_json }}</div>
                
                <h3>Nuclei Findings</h3>
                <div class="json-block">{{ nuclei_json }}</div>
                
                <h3>Exploitation Results</h3>
                <div class="json-block">{{ exploitation_json }}</div>
            </div>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [
                        {{ severity_counts.critical or 0 }},
                        {{ severity_counts.high or 0 }},
                        {{ severity_counts.medium or 0 }},
                        {{ severity_counts.low or 0 }},
                        {{ severity_counts.info or 0 }}
                    ],
                    backgroundColor: [
                        '#dc3545',
                        '#fd7e14', 
                        '#ffc107',
                        '#28a745',
                        '#17a2b8'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    </script>
</body>
</html>
"""


class HTMLReportGenerator:
	def __init__(self, config: AuditorConfig):
		self.config = config

	def _read_json(self, path: Path) -> Any:
		if path.exists():
			try:
				return json.loads(path.read_text())
			except json.JSONDecodeError:
				return None
		return None

	def _extract_version(self, enumeration: Any) -> str | None:
		try:
			if isinstance(enumeration, dict):
				return enumeration.get("server_version")
			return None
		except Exception:
			return None

	def _normalize_severity(self, item: Dict[str, Any]) -> str:
		sev = item.get("severity") or ((item.get("info") or {}).get("severity")) or "unknown"
		return str(sev).lower()

	def _title(self, item: Dict[str, Any]) -> str:
		return item.get("title") or ((item.get("info") or {}).get("name")) or item.get("id") or "finding"

	def generate(self) -> str:
		from datetime import datetime
		
		out_dir = Path(self.config.output_dir)
		enumeration = self._read_json(out_dir / "enumeration.json")
		audit: List[Dict[str, Any]] = self._read_json(out_dir / "audit.json") or []
		nuclei: List[Dict[str, Any]] = self._read_json(out_dir / "nuclei.json") or []
		exploitation: List[Dict[str, Any]] = self._read_json(out_dir / "exploitation.json") or []

		all_findings: List[Dict[str, Any]] = []
		all_findings.extend(audit)
		all_findings.extend(nuclei)
		all_findings.extend(exploitation)

		sev_counts = Counter(self._normalize_severity(f) for f in all_findings)
		sev_order = ["critical", "high", "medium", "low", "info", "unknown"]
		
		top_findings = []
		for f in all_findings:
			sev = self._normalize_severity(f)
			title = self._title(f)
			source = "audit" if f in audit else ("nuclei" if f in nuclei else "exploitation")
			top_findings.append({
				"severity": sev,
				"title": title,
				"source": source,
			})
		top_findings = sorted(top_findings, key=lambda x: sev_order.index(x["severity"]) if x["severity"] in sev_order else len(sev_order))[:10]

		kc_version = self._extract_version(enumeration)
		cves = get_cves_for_version(kc_version) if kc_version else []

		html = HTML_TEMPLATE.format(
			base_url=self.config.base_url,
			realm=self.config.realm,
			version=kc_version,
			timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
			total_findings=len(all_findings),
			severity_counts=sev_counts,
			cves=cves,
			top_findings=top_findings,
			enumeration_json=json.dumps(enumeration, indent=2),
			audit_json=json.dumps(audit, indent=2),
			nuclei_json=json.dumps(nuclei, indent=2),
			exploitation_json=json.dumps(exploitation, indent=2),
		)
		
		html_path = out_dir / "report.html"
		html_path.write_text(html)
		return str(html_path)
