from typing import Any, Dict, List

import requests

from ..core.config import AuditorConfig


class AuditRunner:
	def __init__(self, config: AuditorConfig):
		self.config = config

	def run(self) -> List[Dict[str, Any]]:
		findings: List[Dict[str, Any]] = []
		# Check HTTPS
		if self.config.base_url.startswith("http://"):
			findings.append({
				"id": "transport_insecure",
				"title": "Base URL is not using HTTPS",
				"severity": "medium",
				"remediation": "Serve Keycloak over HTTPS with HSTS enabled.",
			})

		# Check well-known endpoints for security headers
		try:
			resp = requests.get(f"{self.config.base_url}/realms/{self.config.realm}/.well-known/openid-configuration", timeout=10)
			if resp.ok:
				headers = resp.headers
				if "content-security-policy" not in {k.lower() for k in headers.keys()}:
					findings.append({
						"id": "missing_csp",
						"title": "Missing Content-Security-Policy header",
						"severity": "low",
						"remediation": "Configure reverse proxy or Keycloak to set a strict CSP.",
					})
				if "x-frame-options" not in {k.lower() for k in headers.keys()}:
					findings.append({
						"id": "missing_xfo",
						"title": "Missing X-Frame-Options header",
						"severity": "low",
						"remediation": "Set X-Frame-Options: DENY or use CSP frame-ancestors.",
					})
		except requests.RequestException:
			pass

		# Admin console exposure
		try:
			resp = requests.get(f"{self.config.base_url}/admin", timeout=10, allow_redirects=True)
			if resp.status_code == 200:
				findings.append({
					"id": "admin_console_exposed",
					"title": "Admin console accessible",
					"severity": "info",
					"remediation": "Restrict access to admin console via network/policy.",
				})
		except requests.RequestException:
			pass

		return findings
