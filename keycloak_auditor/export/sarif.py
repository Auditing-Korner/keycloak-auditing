import json
from pathlib import Path
from typing import Any, Dict, List

from ..core.config import AuditorConfig


class SARIFExporter:
	def __init__(self, config: AuditorConfig):
		self.config = config

	def _read_json(self, path: Path) -> Any:
		if path.exists():
			try:
				return json.loads(path.read_text())
			except json.JSONDecodeError:
				return None
		return None

	def _normalize_severity(self, item: Dict[str, Any]) -> str:
		sev = item.get("severity") or ((item.get("info") or {}).get("severity")) or "unknown"
		return str(sev).lower()

	def _title(self, item: Dict[str, Any]) -> str:
		return item.get("title") or ((item.get("info") or {}).get("name")) or item.get("id") or "finding"

	def _sarif_severity(self, severity: str) -> str:
		mapping = {
			"critical": "error",
			"high": "error", 
			"medium": "warning",
			"low": "note",
			"info": "note",
		}
		return mapping.get(severity.lower(), "note")

	def export(self) -> str:
		out_dir = Path(self.config.output_dir)
		audit: List[Dict[str, Any]] = self._read_json(out_dir / "audit.json") or []
		nuclei: List[Dict[str, Any]] = self._read_json(out_dir / "nuclei.json") or []
		exploitation: List[Dict[str, Any]] = self._read_json(out_dir / "exploitation.json") or []

		all_findings: List[Dict[str, Any]] = []
		all_findings.extend(audit)
		all_findings.extend(nuclei)
		all_findings.extend(exploitation)

		sarif = {
			"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
			"version": "2.1.0",
			"runs": [
				{
					"tool": {
						"driver": {
							"name": "Keycloak Auditor",
							"version": "0.1.0",
							"informationUri": "https://github.com/your-org/keycloak-auditor",
							"rules": []
						}
					},
					"results": []
				}
			]
		}

		# Build rules and results
		rules = {}
		results = []
		
		for finding in all_findings:
			rule_id = finding.get("id", "unknown")
			severity = self._normalize_severity(finding)
			title = self._title(finding)
			
			# Add rule if not seen
			if rule_id not in rules:
				rules[rule_id] = {
					"id": rule_id,
					"name": title,
					"shortDescription": {
						"text": title
					},
					"helpUri": finding.get("remediation", "")
				}
			
			# Add result
			result = {
				"ruleId": rule_id,
				"level": self._sarif_severity(severity),
				"message": {
					"text": title
				},
				"locations": [
					{
						"physicalLocation": {
							"artifactLocation": {
								"uri": self.config.base_url
							}
						}
					}
				]
			}
			
			# Add evidence if available
			if "evidence" in finding:
				result["message"]["text"] += f" Evidence: {finding['evidence']}"
			
			results.append(result)

		sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
		sarif["runs"][0]["results"] = results

		sarif_path = out_dir / "report.sarif"
		sarif_path.write_text(json.dumps(sarif, indent=2))
		return str(sarif_path)
