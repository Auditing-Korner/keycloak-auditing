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
	# Example entries (placeholder, expand with real data)
	catalog = [
		CVEEntry(
			cve_id="CVE-2023-2198",
			description="Example Keycloak issue (placeholder)",
			severity="high",
			cvss=7.5,
			introduced="20.0.0",
			fixed="20.0.3",
		),
		CVEEntry(
			cve_id="CVE-2022-9999",
			description="Example token handling issue (placeholder)",
			severity="medium",
			cvss=6.3,
			introduced="18.0.0",
			fixed="19.0.0",
		),
	]
	for c in catalog:
		vi = version.parse(c.introduced)
		vf = version.parse(c.fixed) if c.fixed else None
		if v >= vi and (vf is None or v < vf):
			entries.append(c)
	return entries
