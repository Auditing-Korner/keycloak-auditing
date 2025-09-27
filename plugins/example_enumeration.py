"""
Example enumeration plugin for Keycloak Auditor.

This plugin demonstrates how to create custom enumeration checks.
"""

from keycloak_auditor.plugins.base import EnumerationPlugin


class ExampleEnumerationPlugin(EnumerationPlugin):
	"""Example enumeration plugin that gathers custom information."""
	
	def get_name(self) -> str:
		return "example-enumeration"
	
	def get_version(self) -> str:
		return "1.0.0"
	
	def get_description(self) -> str:
		return "Example enumeration plugin demonstrating custom information gathering"
	
	def enumerate(self):
		"""Perform custom enumeration."""
		results = {}
		
		# Example: Check for custom endpoints
		custom_endpoints = [
			"/custom/health",
			"/api/status",
			"/metrics",
			"/info"
		]
		
		available_endpoints = []
		for endpoint in custom_endpoints:
			try:
				response = self.http.request("GET", f"{self.config.base_url}{endpoint}")
				if response.status_code == 200:
					available_endpoints.append({
						"endpoint": endpoint,
						"status": response.status_code,
						"content_type": response.headers.get("content-type", "unknown")
					})
			except Exception:
				pass
		
		results["custom_endpoints"] = available_endpoints
		
		# Example: Check server information
		try:
			response = self.http.request("GET", f"{self.config.base_url}/")
			server_header = response.headers.get("server", "unknown")
			results["server_info"] = {
				"server_header": server_header,
				"response_time": response.elapsed.total_seconds() if hasattr(response, 'elapsed') else None
			}
		except Exception:
			results["server_info"] = {"error": "Could not retrieve server information"}
		
		return results
