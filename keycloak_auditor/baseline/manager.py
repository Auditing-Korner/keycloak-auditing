import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.config import AuditorConfig


class BaselineManager:
	def __init__(self, config: AuditorConfig):
		self.config = config
		self.baseline_dir = Path(config.output_dir) / "baselines"

	def _ensure_baseline_dir(self) -> None:
		"""Ensure baseline directory exists."""
		self.baseline_dir.mkdir(parents=True, exist_ok=True)

	def _get_baseline_path(self, name: str) -> Path:
		"""Get path for baseline file."""
		return self.baseline_dir / f"{name}.json"

	def _read_json(self, path: Path) -> Any:
		"""Read JSON file safely."""
		if path.exists():
			try:
				return json.loads(path.read_text())
			except json.JSONDecodeError:
				return None
		return None

	def _write_json(self, path: Path, data: Any) -> None:
		"""Write JSON file safely."""
		path.write_text(json.dumps(data, indent=2))

	def create_baseline(self, name: str, description: str = "") -> str:
		"""Create a baseline from current scan results."""
		self._ensure_baseline_dir()
		
		out_dir = Path(self.config.output_dir)
		baseline_data = {
			"metadata": {
				"name": name,
				"description": description,
				"created_at": datetime.now().isoformat(),
				"base_url": self.config.base_url,
				"realm": self.config.realm,
			},
			"enumeration": self._read_json(out_dir / "enumeration.json"),
			"audit": self._read_json(out_dir / "audit.json") or [],
			"nuclei": self._read_json(out_dir / "nuclei.json") or [],
			"exploitation": self._read_json(out_dir / "exploitation.json") or [],
		}
		
		baseline_path = self._get_baseline_path(name)
		self._write_json(baseline_path, baseline_data)
		
		return str(baseline_path)

	def list_baselines(self) -> List[Dict[str, Any]]:
		"""List all available baselines."""
		self._ensure_baseline_dir()
		
		baselines = []
		for baseline_file in self.baseline_dir.glob("*.json"):
			data = self._read_json(baseline_file)
			if data and "metadata" in data:
				baselines.append({
					"name": baseline_file.stem,
					"path": str(baseline_file),
					"metadata": data["metadata"]
				})
		
		return sorted(baselines, key=lambda x: x["metadata"]["created_at"], reverse=True)

	def compare_with_baseline(self, baseline_name: str) -> Dict[str, Any]:
		"""Compare current scan results with a baseline."""
		baseline_path = self._get_baseline_path(baseline_name)
		baseline_data = self._read_json(baseline_path)
		
		if not baseline_data:
			raise FileNotFoundError(f"Baseline '{baseline_name}' not found")
		
		out_dir = Path(self.config.output_dir)
		current_data = {
			"enumeration": self._read_json(out_dir / "enumeration.json"),
			"audit": self._read_json(out_dir / "audit.json") or [],
			"nuclei": self._read_json(out_dir / "nuclei.json") or [],
			"exploitation": self._read_json(out_dir / "exploitation.json") or [],
		}
		
		comparison = {
			"baseline": baseline_data["metadata"],
			"current": {
				"base_url": self.config.base_url,
				"realm": self.config.realm,
				"compared_at": datetime.now().isoformat(),
			},
			"changes": {
				"enumeration": self._compare_enumeration(
					baseline_data.get("enumeration", {}),
					current_data.get("enumeration", {})
				),
				"audit": self._compare_findings(
					baseline_data.get("audit", []),
					current_data.get("audit", [])
				),
				"nuclei": self._compare_findings(
					baseline_data.get("nuclei", []),
					current_data.get("nuclei", [])
				),
				"exploitation": self._compare_findings(
					baseline_data.get("exploitation", []),
					current_data.get("exploitation", [])
				),
			}
		}
		
		return comparison

	def _compare_enumeration(self, baseline: Dict, current: Dict) -> Dict[str, Any]:
		"""Compare enumeration results."""
		changes = {
			"added": {},
			"removed": {},
			"modified": {},
			"unchanged": {}
		}
		
		# Compare server version
		baseline_version = baseline.get("server_version")
		current_version = current.get("server_version")
		if baseline_version != current_version:
			changes["modified"]["server_version"] = {
				"baseline": baseline_version,
				"current": current_version
			}
		else:
			changes["unchanged"]["server_version"] = current_version
		
		# Compare realm info counts
		baseline_realm = baseline.get("realm_info", {})
		current_realm = current.get("realm_info", {})
		
		for key in set(baseline_realm.keys()) | set(current_realm.keys()):
			baseline_val = baseline_realm.get(key)
			current_val = current_realm.get(key)
			
			if baseline_val != current_val:
				changes["modified"][f"realm_info.{key}"] = {
					"baseline": baseline_val,
					"current": current_val
				}
			else:
				changes["unchanged"][f"realm_info.{key}"] = current_val
		
		return changes

	def _compare_findings(self, baseline: List[Dict], current: List[Dict]) -> Dict[str, Any]:
		"""Compare findings lists."""
		baseline_ids = {f.get("id", f.get("title", str(i))) for i, f in enumerate(baseline)}
		current_ids = {f.get("id", f.get("title", str(i))) for i, f in enumerate(current)}
		
		added_ids = current_ids - baseline_ids
		removed_ids = baseline_ids - current_ids
		common_ids = baseline_ids & current_ids
		
		changes = {
			"added": [f for f in current if f.get("id", f.get("title", "")) in added_ids],
			"removed": [f for f in baseline if f.get("id", f.get("title", "")) in removed_ids],
			"modified": [],
			"unchanged": []
		}
		
		# Check for modifications in common findings
		baseline_by_id = {f.get("id", f.get("title", "")): f for f in baseline}
		current_by_id = {f.get("id", f.get("title", "")): f for f in current}
		
		for finding_id in common_ids:
			baseline_finding = baseline_by_id[finding_id]
			current_finding = current_by_id[finding_id]
			
			if baseline_finding != current_finding:
				changes["modified"].append({
					"id": finding_id,
					"baseline": baseline_finding,
					"current": current_finding
				})
			else:
				changes["unchanged"].append(current_finding)
		
		return changes

	def generate_drift_report(self, baseline_name: str) -> str:
		"""Generate a drift report comparing current state with baseline."""
		comparison = self.compare_with_baseline(baseline_name)
		
		report = f"""# Drift Report: {baseline_name}

## Summary
- **Baseline**: {comparison['baseline']['name']} (created: {comparison['baseline']['created_at']})
- **Current**: {comparison['current']['compared_at']}
- **Target**: {comparison['current']['base_url']} (realm: {comparison['current']['realm']})

## Changes Detected

### Enumeration Changes
"""
		
		enum_changes = comparison["changes"]["enumeration"]
		if enum_changes["modified"]:
			report += "\n**Modified:**\n"
			for key, change in enum_changes["modified"].items():
				report += f"- {key}: {change['baseline']} → {change['current']}\n"
		
		if enum_changes["added"]:
			report += "\n**Added:**\n"
			for key, value in enum_changes["added"].items():
				report += f"- {key}: {value}\n"
		
		if enum_changes["removed"]:
			report += "\n**Removed:**\n"
			for key, value in enum_changes["removed"].items():
				report += f"- {key}: {value}\n"
		
		# Add findings changes
		for category in ["audit", "nuclei", "exploitation"]:
			changes = comparison["changes"][category]
			report += f"\n### {category.title()} Changes\n"
			
			if changes["added"]:
				report += f"\n**New Findings ({len(changes['added'])}):**\n"
				for finding in changes["added"]:
					title = finding.get("title", finding.get("id", "Unknown"))
					severity = finding.get("severity", "unknown")
					report += f"- [{severity.upper()}] {title}\n"
			
			if changes["removed"]:
				report += f"\n**Resolved Findings ({len(changes['removed'])}):**\n"
				for finding in changes["removed"]:
					title = finding.get("title", finding.get("id", "Unknown"))
					severity = finding.get("severity", "unknown")
					report += f"- [{severity.upper()}] {title}\n"
			
			if changes["modified"]:
				report += f"\n**Modified Findings ({len(changes['modified'])}):**\n"
				for change in changes["modified"]:
					report += f"- {change['id']}\n"
		
		# Save report
		report_path = Path(self.config.output_dir) / f"drift-{baseline_name}.md"
		report_path.write_text(report)
		
		# Save comparison data
		comparison_path = Path(self.config.output_dir) / f"drift-{baseline_name}.json"
		comparison_path.write_text(json.dumps(comparison, indent=2))
		
		return str(report_path)
