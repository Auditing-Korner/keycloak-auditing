"""
Example audit plugin for Keycloak Auditor.

This plugin demonstrates how to create custom audit checks.
"""

from keycloak_auditor.plugins.base import AuditPlugin


class ExampleAuditPlugin(AuditPlugin):
	"""Example audit plugin that checks for custom security issues."""
	
	def get_name(self) -> str:
		return "example-audit"
	
	def get_version(self) -> str:
		return "1.0.0"
	
	def get_description(self) -> str:
		return "Example audit plugin demonstrating custom security checks"
	
	def audit(self):
		"""Perform custom audit checks."""
		findings = []
		
		# Example check: Verify custom header
		try:
			response = self.http.request("GET", f"{self.config.base_url}/realms/{self.config.realm}/.well-known/openid-configuration")
			if response.ok:
				# Check for custom security header
				if "x-custom-security-header" not in response.headers:
					findings.append({
						"id": "missing_custom_header",
						"title": "Missing custom security header",
						"severity": "low",
						"description": "The x-custom-security-header is not present",
						"remediation": "Add x-custom-security-header to all responses"
					})
		except Exception:
			pass
		
		# Example check: Verify specific endpoint
		try:
			response = self.http.request("GET", f"{self.config.base_url}/health")
			if response.status_code == 404:
				findings.append({
					"id": "health_endpoint_missing",
					"title": "Health endpoint not found",
					"severity": "info",
					"description": "The /health endpoint is not available",
					"remediation": "Consider implementing a health check endpoint"
				})
		except Exception:
			pass
		
		return findings
