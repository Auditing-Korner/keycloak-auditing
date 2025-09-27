from typing import Any, Dict, List
import urllib.parse
import xml.etree.ElementTree as ET

from ..core.config import AuditorConfig
from ..core.http import ThrottledRequester
from ..plugins.manager import PluginManager


class AuditRunner:
	def __init__(self, config: AuditorConfig):
		self.config = config
		self.http = ThrottledRequester(config)

	def _headers(self, token: str | None = None) -> Dict[str, str]:
		headers: Dict[str, str] = {}
		if token:
			headers["Authorization"] = f"Bearer {token}"
		return headers

	def _pkce_enforcement_check(self) -> Dict[str, Any] | None:
		"""Probe whether authorization code flow accepts requests without PKCE.
		This is a heuristic against the 'account' public client.
		"""
		try:
			params = {
				"client_id": "account",
				"redirect_uri": "https://example.com",
				"response_type": "code",
				"scope": "openid",
				# Intentionally omitting code_challenge & code_challenge_method
			}
			url = f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/auth"
			resp = self.http.request("GET", url, params=params, allow_redirects=False)
			# If server immediately redirects to redirect_uri (302 with Location=https://example.com), that's suspicious
			loc = resp.headers.get("location", "")
			if 300 <= resp.status_code < 400 and "https://example.com" in loc:
				return {
					"id": "pkce_not_enforced",
					"title": "PKCE may not be enforced for authorization code flow",
					"severity": "medium",
					"evidence": loc,
					"remediation": "Require PKCE for public clients and enforce code_challenge on auth requests.",
				}
		except Exception:
			return None
		return None

	def _redirect_uri_exact_match_check(self) -> Dict[str, Any] | None:
		"""Probe if redirect_uri validation is overly permissive by adding a suffix path segment."""
		try:
			base_redirect = "https://example.com/app"
			permissive_redirect = base_redirect + "/evil"
			params = {
				"client_id": "account",
				"redirect_uri": permissive_redirect,
				"response_type": "code",
				"scope": "openid",
			}
			url = f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/auth"
			resp = self.http.request("GET", url, params=params, allow_redirects=False)
			loc = resp.headers.get("location", "")
			if 300 <= resp.status_code < 400 and permissive_redirect in loc:
				return {
					"id": "redirect_uri_permissive",
					"title": "Redirect URI may not require exact match",
					"severity": "medium",
					"evidence": loc,
					"remediation": "Configure client redirect URIs to exact values; avoid wildcards and suffix matches.",
				}
		except Exception:
			return None
		return None

	def _saml_metadata_check(self) -> List[Dict[str, Any]]:
		"""Fetch SAML metadata and check for signature requirements where possible."""
		findings: List[Dict[str, Any]] = []
		try:
			url = f"{self.config.base_url}/realms/{self.config.realm}/protocol/saml/descriptor"
			resp = self.http.request("GET", url)
			if not resp.ok or not resp.text.strip().startswith("<"):
				return findings
			root = ET.fromstring(resp.text)
			# Namespaces commonly used in SAML metadata
			ns = {
				"md": "urn:oasis:names:tc:SAML:2.0:metadata",
				"ds": "http://www.w3.org/2000/09/xmldsig#",
			}
			# Check WantAssertionsSigned on SPSSODescriptor elements
			for sp in root.findall(".//md:SPSSODescriptor", ns):
				want_signed = sp.get("WantAssertionsSigned") or sp.get("AuthnRequestsSigned")
				if str(want_signed).lower() not in {"true", "1"}:
					findings.append({
						"id": "saml_assertions_not_signed",
						"title": "SAML assertions or authn requests may not require signatures",
						"severity": "medium",
						"remediation": "Enable WantAssertionsSigned and AuthnRequestsSigned in SAML client settings.",
					})
		except Exception:
			return findings
		return findings

	def run(self) -> List[Dict[str, Any]]:
		findings: List[Dict[str, Any]] = []
		# Transport & headers quick checks
		if self.config.base_url.startswith("http://"):
			findings.append({
				"id": "transport_insecure",
				"title": "Base URL is not using HTTPS",
				"severity": "medium",
				"remediation": "Serve Keycloak over HTTPS with HSTS enabled.",
			})

		# Well-known headers presence
		try:
			resp = self.http.request("GET", f"{self.config.base_url}/realms/{self.config.realm}/.well-known/openid-configuration")
			if resp.ok:
				headers = {k.lower(): v for k, v in resp.headers.items()}
				if "content-security-policy" not in headers:
					findings.append({
						"id": "missing_csp",
						"title": "Missing Content-Security-Policy header",
						"severity": "low",
						"remediation": "Configure reverse proxy or Keycloak to set a strict CSP.",
					})
				if "x-frame-options" not in headers:
					findings.append({
						"id": "missing_xfo",
						"title": "Missing X-Frame-Options header",
						"severity": "low",
						"remediation": "Set X-Frame-Options: DENY or use CSP frame-ancestors.",
					})
		except Exception:
			pass

		# Admin console exposure
		try:
			resp = self.http.request("GET", f"{self.config.base_url}/admin", allow_redirects=True)
			if resp.status_code == 200:
				findings.append({
					"id": "admin_console_exposed",
					"title": "Admin console accessible",
					"severity": "info",
					"remediation": "Restrict access to admin console via network/policy.",
				})
		except Exception:
			pass

		# PKCE enforcement heuristic
		pkce = self._pkce_enforcement_check()
		if pkce:
			findings.append(pkce)

		# Redirect URI exact-match heuristic
		redir = self._redirect_uri_exact_match_check()
		if redir:
			findings.append(redir)

		# SAML metadata checks
		findings.extend(self._saml_metadata_check())

		# Run audit plugins
		try:
			plugin_manager = PluginManager(self.config)
			plugin_manager.load_plugins()
			plugin_findings = plugin_manager.run_audit_plugins()
			findings.extend(plugin_findings)
		except Exception:
			pass

		return findings
