import json
from typing import Any, Dict

import requests

from ..core.config import AuditorConfig


class KeycloakEnumerator:
	def __init__(self, config: AuditorConfig):
		self.config = config

	def _get(self, path: str) -> requests.Response:
		url = f"{self.config.base_url}{path}"
		headers = {}
		if self.config.token:
			headers["Authorization"] = f"Bearer {self.config.token}"
		return requests.get(url, headers=headers, timeout=15, verify=True)

	def _post(self, path: str, data: Dict[str, Any]) -> requests.Response:
		url = f"{self.config.base_url}{path}"
		headers = {"Content-Type": "application/x-www-form-urlencoded"}
		return requests.post(url, headers=headers, data=data, timeout=15, verify=True)

	def _maybe_get_admin_token(self) -> str | None:
		if self.config.token:
			return self.config.token
		if self.config.client_id and self.config.client_secret:
			# Client credentials against token endpoint
			realm = self.config.realm
			resp = self._post(
				f"/realms/{realm}/protocol/openid-connect/token",
				{
					"grant_type": "client_credentials",
					"client_id": self.config.client_id,
					"client_secret": self.config.client_secret,
				},
			)
			if resp.ok:
				return resp.json().get("access_token")
		return None

	def run(self) -> Dict[str, Any]:
		result: Dict[str, Any] = {}

		# Version info (Keycloak exposes at /auth by older, and /.well-known? Using health and version endpoint)
		version_endpoints = [
			"/realms/master/.well-known/openid-configuration",
			"/realms/%s/.well-known/openid-configuration" % self.config.realm,
		]
		version_data: Dict[str, Any] = {}
		for ep in version_endpoints:
			try:
				resp = self._get(ep)
				if resp.ok:
					data = resp.json()
					issuer = data.get("issuer")
					version_data[ep] = {"issuer": issuer, "authorization_endpoint": data.get("authorization_endpoint")}
			except requests.RequestException:
				continue
		result["oidc_well_known"] = version_data

		# Realms enumeration: if unauth allowed, usually not; attempt if token available
		admin_token = self._maybe_get_admin_token()
		realms = []
		if admin_token:
			try:
				resp = requests.get(
					f"{self.config.base_url}/admin/realms",
					headers={"Authorization": f"Bearer {admin_token}"},
					timeout=15,
				)
				if resp.ok:
					realms = [r.get("realm") for r in resp.json() if isinstance(r, dict)]
			except requests.RequestException:
				pass
		result["realms"] = realms

		# Clients, roles, users (counts) for target realm if token permits
		realm = self.config.realm
		realm_info: Dict[str, Any] = {}
		if admin_token:
			base = f"{self.config.base_url}/admin/realms/{realm}"
			try:
				clients = requests.get(f"{base}/clients", headers={"Authorization": f"Bearer {admin_token}"}, timeout=20)
				if clients.ok:
					realm_info["clients_count"] = len(clients.json())
				roles = requests.get(f"{base}/roles", headers={"Authorization": f"Bearer {admin_token}"}, timeout=20)
				if roles.ok:
					realm_info["roles_count"] = len(roles.json())
				users = requests.get(f"{base}/users?max=1&first=0", headers={"Authorization": f"Bearer {admin_token}"}, timeout=20)
				if users.ok:
					realm_info["users_accessible"] = True
			except requests.RequestException:
				pass
		result["realm_info"] = realm_info

		return result
