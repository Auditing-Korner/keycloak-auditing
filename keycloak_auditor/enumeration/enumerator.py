import json
from typing import Any, Dict, List

from ..core.config import AuditorConfig
from ..core.http import ThrottledRequester


class KeycloakEnumerator:
	def __init__(self, config: AuditorConfig):
		self.config = config
		self.http = ThrottledRequester(config)

	def _headers(self, token: str | None = None) -> Dict[str, str]:
		headers: Dict[str, str] = {}
		if token:
			headers["Authorization"] = f"Bearer {token}"
		return headers

	def _well_known(self) -> Dict[str, Any]:
		data: Dict[str, Any] = {}
		for ep in [
			f"{self.config.base_url}/realms/master/.well-known/openid-configuration",
			f"{self.config.base_url}/realms/{self.config.realm}/.well-known/openid-configuration",
			f"{self.config.base_url}/realms/{self.config.realm}/.well-known/uma2-configuration",
		]:
			try:
				resp = self.http.request("GET", ep)
				if resp.ok:
					data[ep] = resp.json()
			except Exception:
				continue
		return data

	def _client_credentials_token(self) -> str | None:
		if self.config.token:
			return self.config.token
		if self.config.client_id and self.config.client_secret:
			try:
				resp = self.http.request(
					"POST",
					f"{self.config.base_url}/realms/{self.config.realm}/protocol/openid-connect/token",
					headers={"Content-Type": "application/x-www-form-urlencoded"},
					data={
						"grant_type": "client_credentials",
						"client_id": self.config.client_id,
						"client_secret": self.config.client_secret,
					},
				)
				if resp.ok:
					return resp.json().get("access_token")
			except Exception:
				return None
		return None

	def _admin_list(self, token: str, path: str) -> List[Any] | None:
		try:
			resp = self.http.request("GET", f"{self.config.base_url}{path}", headers=self._headers(token))
			if resp.ok:
				j = resp.json()
				return j if isinstance(j, list) else None
		except Exception:
			return None
		return None

	def run(self) -> Dict[str, Any]:
		result: Dict[str, Any] = {}
		result["oidc_well_known"] = self._well_known()

		token = self._client_credentials_token()
		# version via serverinfo
		if token:
			try:
				resp = self.http.request("GET", f"{self.config.base_url}/admin/serverinfo", headers=self._headers(token))
				if resp.ok:
					info = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else None
					if isinstance(info, dict):
						vers = info.get("systemInfo", {}).get("version") or info.get("version")
						if vers:
							result["server_version"] = vers
			except Exception:
				pass

		realms: List[str] = []
		if token:
			realms_data = self._admin_list(token, "/admin/realms")
			if realms_data:
				realms = [r.get("realm") for r in realms_data if isinstance(r, dict)]
		result["realms"] = realms

		realm = self.config.realm
		realm_info: Dict[str, Any] = {}
		if token:
			base = f"/admin/realms/{realm}"
			clients = self._admin_list(token, f"{base}/clients") or []
			roles = self._admin_list(token, f"{base}/roles") or []
			groups = self._admin_list(token, f"{base}/groups") or []
			idps = self._admin_list(token, f"{base}/identity-provider/instances") or []
			flows = self._admin_list(token, f"{base}/authentication/flows") or []
			client_scopes = self._admin_list(token, f"{base}/client-scopes") or []
			components = self._admin_list(token, f"{base}/components") or []
			realm_info.update({
				"clients_count": len(clients),
				"roles_count": len(roles),
				"groups_count": len(groups),
				"idps_count": len(idps),
				"flows_count": len(flows),
				"client_scopes_count": len(client_scopes),
				"components_count": len(components),
			})
		result["realm_info"] = realm_info

		try:
			admin_resp = self.http.request("GET", f"{self.config.base_url}/admin", allow_redirects=True)
			result["admin_console_status"] = admin_resp.status_code
		except Exception:
			result["admin_console_status"] = None

		return result
