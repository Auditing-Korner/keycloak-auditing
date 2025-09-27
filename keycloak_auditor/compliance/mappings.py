from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class ComplianceCheck:
	control_id: str
	title: str
	description: str
	framework: str
	severity: str
	pass_condition: str
	fail_condition: str


# CIS Controls mapping for Keycloak
CIS_CONTROLS = [
	ComplianceCheck(
		control_id="CIS-1.1",
		title="Use HTTPS for all Keycloak communications",
		description="Ensure Keycloak is served over HTTPS to protect authentication data",
		framework="CIS",
		severity="high",
		pass_condition="Base URL uses HTTPS",
		fail_condition="Base URL uses HTTP"
	),
	ComplianceCheck(
		control_id="CIS-1.2",
		title="Implement security headers",
		description="Configure Content-Security-Policy and X-Frame-Options headers",
		framework="CIS",
		severity="medium",
		pass_condition="CSP and X-Frame-Options headers present",
		fail_condition="Missing security headers"
	),
	ComplianceCheck(
		control_id="CIS-1.3",
		title="Restrict admin console access",
		description="Limit access to Keycloak admin console",
		framework="CIS",
		severity="medium",
		pass_condition="Admin console not publicly accessible",
		fail_condition="Admin console publicly accessible"
	),
	ComplianceCheck(
		control_id="CIS-1.4",
		title="Enforce PKCE for public clients",
		description="Require Proof Key for Code Exchange for OAuth2 public clients",
		framework="CIS",
		severity="high",
		pass_condition="PKCE enforced for authorization code flow",
		fail_condition="PKCE not enforced"
	),
	ComplianceCheck(
		control_id="CIS-1.5",
		title="Validate redirect URIs exactly",
		description="Ensure redirect URI validation is strict and exact",
		framework="CIS",
		severity="medium",
		pass_condition="Redirect URIs require exact match",
		fail_condition="Redirect URIs allow permissive matching"
	),
]

# OWASP ASVS mapping for Keycloak
OWASP_CONTROLS = [
	ComplianceCheck(
		control_id="V2.1.1",
		title="Verify secure transport",
		description="Verify that all authentication exchanges are protected with secure transport",
		framework="OWASP",
		severity="high",
		pass_condition="HTTPS enforced",
		fail_condition="HTTP allowed"
	),
	ComplianceCheck(
		control_id="V2.1.2",
		title="Verify authentication error handling",
		description="Verify that authentication errors are handled securely",
		framework="OWASP",
		severity="medium",
		pass_condition="No information disclosure in error messages",
		fail_condition="Sensitive information in error responses"
	),
	ComplianceCheck(
		control_id="V2.1.3",
		title="Verify session management",
		description="Verify that session management is secure",
		framework="OWASP",
		severity="high",
		pass_condition="Secure session cookies with proper flags",
		fail_condition="Insecure session cookie configuration"
	),
	ComplianceCheck(
		control_id="V2.1.4",
		title="Verify OAuth2/OpenID Connect implementation",
		description="Verify secure OAuth2/OpenID Connect implementation",
		framework="OWASP",
		severity="high",
		pass_condition="PKCE enforced, secure redirect URIs",
		fail_condition="Weak OAuth2/OpenID Connect configuration"
	),
	ComplianceCheck(
		control_id="V2.1.5",
		title="Verify SAML implementation",
		description="Verify secure SAML implementation",
		framework="OWASP",
		severity="medium",
		pass_condition="SAML assertions require signatures",
		fail_condition="SAML assertions not signed"
	),
]


def get_compliance_checks(framework: Optional[str] = None) -> List[ComplianceCheck]:
	"""Get compliance checks for specified framework or all frameworks."""
	all_checks = CIS_CONTROLS + OWASP_CONTROLS
	if framework:
		return [check for check in all_checks if check.framework.upper() == framework.upper()]
	return all_checks


def map_findings_to_compliance(findings: List[Dict], checks: List[ComplianceCheck]) -> Dict[str, List[Dict]]:
	"""Map audit findings to compliance controls."""
	compliance_results = {}
	
	for check in checks:
		compliance_results[check.control_id] = {
			"check": check,
			"status": "unknown",
			"findings": [],
			"pass_count": 0,
			"fail_count": 0
		}
	
	# Simple mapping based on finding IDs and descriptions
	for finding in findings:
		finding_id = finding.get("id", "").lower()
		finding_title = finding.get("title", "").lower()
		
		for check in checks:
			check_id = check.control_id.lower()
			
			# Map based on finding patterns
			if "transport_insecure" in finding_id and "https" in check.description.lower():
				compliance_results[check.control_id]["findings"].append(finding)
				compliance_results[check.control_id]["fail_count"] += 1
			elif "missing_csp" in finding_id or "missing_xfo" in finding_id:
				if "header" in check.description.lower():
					compliance_results[check.control_id]["findings"].append(finding)
					compliance_results[check.control_id]["fail_count"] += 1
			elif "admin_console_exposed" in finding_id:
				if "admin" in check.description.lower():
					compliance_results[check.control_id]["findings"].append(finding)
					compliance_results[check.control_id]["fail_count"] += 1
			elif "pkce_not_enforced" in finding_id:
				if "pkce" in check.description.lower():
					compliance_results[check.control_id]["findings"].append(finding)
					compliance_results[check.control_id]["fail_count"] += 1
			elif "redirect_uri_permissive" in finding_id:
				if "redirect" in check.description.lower():
					compliance_results[check.control_id]["findings"].append(finding)
					compliance_results[check.control_id]["fail_count"] += 1
			elif "saml_assertions_not_signed" in finding_id:
				if "saml" in check.description.lower():
					compliance_results[check.control_id]["findings"].append(finding)
					compliance_results[check.control_id]["fail_count"] += 1
	
	# Determine pass/fail status
	for control_id, result in compliance_results.items():
		if result["fail_count"] > 0:
			result["status"] = "fail"
		elif result["pass_count"] > 0:
			result["status"] = "pass"
		else:
			result["status"] = "unknown"
	
	return compliance_results

