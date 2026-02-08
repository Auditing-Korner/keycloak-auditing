from dataclasses import dataclass
from typing import List

from packaging import version


@dataclass
class CVEEntry:
	cve_id: str
	description: str
	severity: str
	cvss: float
	introduced: str  # version >= introduced
	fixed: str | None  # version < fixed means vulnerable; None if unfixed


def get_cves_for_version(kc_version: str) -> List[CVEEntry]:
	v = version.parse(kc_version)
	entries: List[CVEEntry] = []
	# Real Keycloak CVEs
	catalog = [
		CVEEntry(
			cve_id="CVE-2022-1245",
			description="Privilege escalation via token exchange; client can exchange tokens for any target client without authorization.",
			severity="high",
			cvss=8.1,
			introduced="0.0.0",
			fixed="18.0.0",
		),
		CVEEntry(
			cve_id="CVE-2024-4540",
			description="Information disclosure in OAuth 2.0 Pushed Authorization Requests (PAR) via plain text KC_RESTART cookie.",
			severity="high",
			cvss=7.5,
			introduced="0.0.0",
			fixed="24.0.0",
		),
		CVEEntry(
			cve_id="CVE-2022-2232",
			description="LDAP query vulnerability allowing access to existing usernames on the server.",
			severity="high",
			cvss=7.5,
			introduced="0.0.0",
			fixed="19.0.0",
		),
		CVEEntry(
			cve_id="CVE-2024-4629",
			description="Brute-force bypass via timing attack and multiple simultaneous login race conditions.",
			severity="medium",
			cvss=6.5,
			introduced="0.0.0",
			fixed="25.0.0",
		),
		CVEEntry(
			cve_id="CVE-2023-6544",
			description="Permissive regex in TrustedDomains allowing malicious dynamic client registration.",
			severity="medium",
			cvss=5.4,
			introduced="0.0.0",
			fixed="23.0.0",
		),
	]
	for c in catalog:
		vi = version.parse(c.introduced)
		vf = version.parse(c.fixed) if c.fixed else None
		if v >= vi and (vf is None or v < vf):
			entries.append(c)
	return entries
