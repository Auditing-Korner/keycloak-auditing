import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from ..core.config import AuditorConfig


class NucleiScanner:
	def __init__(self, config: AuditorConfig):
		self.config = config

	def run(self, use_workflow: bool = False) -> List[Dict[str, Any]]:
		binary = shutil.which(self.config.nuclei_path) or self.config.nuclei_path
		output_path = Path(self.config.output_dir) / "nuclei.jsonl"
		cmd = [
			binary,
			"-u",
			self.config.base_url,
			"-jsonl",
			"-silent",
			"-no-color",
			"-o",
			str(output_path),
		]
		templates_path = Path(self.config.nuclei_templates)
		if use_workflow:
			workflow = templates_path / "keycloak-security-workflow.yaml"
			if workflow.exists():
				cmd.extend(["-w", str(workflow)])
			else:
				cmd.extend(["-t", str(templates_path)])
		else:
			cmd.extend(["-t", str(templates_path)])

		try:
			subprocess.run(cmd, check=False)
		except FileNotFoundError:
			return [{
				"id": "nuclei_missing",
				"info": {"name": "Nuclei binary not found"},
				"severity": "info",
			}]

		results: List[Dict[str, Any]] = []
		if output_path.exists():
			for line in output_path.read_text().splitlines():
				try:
					results.append(json.loads(line))
				except json.JSONDecodeError:
					continue
		return results
