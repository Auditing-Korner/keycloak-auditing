import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Set
from urllib.parse import urlsplit

from ..core.config import AuditorConfig


class NucleiScanner:
	def __init__(self, config: AuditorConfig):
		self.config = config

	def _build_targets_from_wordlists(self) -> Path | None:
		try:
			wl_dir = Path(self.config.wordlists_dir)
			dirs_file = wl_dir / "keycloak-directories.txt"
			subs_file = wl_dir / "keycloak-subdomains.txt"
			if not dirs_file.exists():
				return None
			split = urlsplit(self.config.base_url)
			scheme = split.scheme or "https"
			host = split.netloc
			# directories
			dirs: List[str] = [line.strip() for line in dirs_file.read_text().splitlines() if line.strip() and not line.startswith("#")]
			dirs = [d.replace("{realm}", self.config.realm) for d in dirs]
			# subdomains
			hosts: Set[str] = {host}
			if subs_file.exists():
				subs = [line.strip() for line in subs_file.read_text().splitlines() if line.strip() and not line.startswith("#")]
				for sub in subs:
					hosts.add(f"{sub}.{host}")
			# build urls
			urls: Set[str] = set()
			for h in hosts:
				for d in dirs:
					path = d if d.startswith("/") else f"/{d}"
					urls.add(f"{scheme}://{h}{path}")
			out_file = Path(self.config.output_dir) / "targets.txt"
			out_file.write_text("\n".join(sorted(urls)))
			return out_file
		except Exception:
			return None

	def run(self, use_workflow: bool = False) -> List[Dict[str, Any]]:
		binary = shutil.which(self.config.nuclei_path) or self.config.nuclei_path
		output_path = Path(self.config.output_dir) / "nuclei.jsonl"
		cmd = [
			binary,
			"-jsonl",
			"-silent",
			"-no-color",
			"-o",
			str(output_path),
			"-rate-limit",
			str(max(int(self.config.rate_limit_rps), 1)),
			"-timeout",
			str(self.config.http_timeout_seconds),
		]
		# Auth header if token provided
		if self.config.token:
			cmd.extend(["-H", f"Authorization: Bearer {self.config.token}"])

		# targets
		targets_list: Path | None = None
		if self.config.use_wordlists:
			targets_list = self._build_targets_from_wordlists()
		if targets_list and targets_list.exists():
			cmd.extend(["-l", str(targets_list)])
		else:
			cmd.extend(["-u", self.config.base_url])

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
