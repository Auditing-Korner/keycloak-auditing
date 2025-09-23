
	# Keycloak Audit Report

	- Base URL: https://keycloak.cfappsecurity.com
	- Realm: master
	- Version: unknown

	## Summary
	- Enumeration items: 4
	- Audit findings: 2
	- Nuclei findings: 1
	- Exploit attempts: 0
	- CVEs matched: 0

	### Severity Breakdown (All Sources)
	| Severity | Count |
	|---|---:|
	| Low | 1 |
	| Info | 2 |
	

	### Top Findings
	
	- [Low] Missing Content-Security-Policy header
	
	- [Info] Admin console accessible
	
	- [Info] Nuclei binary not found
	

	## CVE Mapping
	
	No CVEs matched the detected version.
	

	## Enumeration
	```
	{
  "admin_console_status": 200,
  "oidc_well_known": {
    "https://keycloak.cfappsecurity.com/realms/master/.well-known/openid-configuration": {
      "acr_values_supported": [
        "0",
        "1"
      ],
      "authorization_encryption_alg_values_supported": [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5"
      ],
      "authorization_encryption_enc_values_supported": [
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512"
      ],
      "authorization_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/auth",
      "authorization_response_iss_parameter_supported": true,
      "authorization_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "backchannel_authentication_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/ext/ciba/auth",
      "backchannel_authentication_request_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "ES256",
        "RS256",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "backchannel_logout_session_supported": true,
      "backchannel_logout_supported": true,
      "backchannel_token_delivery_modes_supported": [
        "poll",
        "ping"
      ],
      "check_session_iframe": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/login-status-iframe.html",
      "claim_types_supported": [
        "normal"
      ],
      "claims_parameter_supported": true,
      "claims_supported": [
        "aud",
        "sub",
        "iss",
        "auth_time",
        "name",
        "given_name",
        "family_name",
        "preferred_username",
        "email",
        "acr"
      ],
      "code_challenge_methods_supported": [
        "plain",
        "S256"
      ],
      "device_authorization_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/auth/device",
      "end_session_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/logout",
      "frontchannel_logout_session_supported": true,
      "frontchannel_logout_supported": true,
      "grant_types_supported": [
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "client_credentials",
        "urn:openid:params:grant-type:ciba",
        "urn:ietf:params:oauth:grant-type:device_code"
      ],
      "id_token_encryption_alg_values_supported": [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5"
      ],
      "id_token_encryption_enc_values_supported": [
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512"
      ],
      "id_token_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "introspection_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/token/introspect",
      "introspection_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
      ],
      "introspection_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "issuer": "https://keycloak.cfappsecurity.com/realms/master",
      "jwks_uri": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/certs",
      "mtls_endpoint_aliases": {
        "backchannel_authentication_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/ext/ciba/auth",
        "device_authorization_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/auth/device",
        "introspection_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/token/introspect",
        "pushed_authorization_request_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/ext/par/request",
        "registration_endpoint": "https://keycloak.cfappsecurity.com/realms/master/clients-registrations/openid-connect",
        "revocation_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/revoke",
        "token_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/token",
        "userinfo_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/userinfo"
      },
      "pushed_authorization_request_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/ext/par/request",
      "registration_endpoint": "https://keycloak.cfappsecurity.com/realms/master/clients-registrations/openid-connect",
      "request_object_encryption_alg_values_supported": [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5"
      ],
      "request_object_encryption_enc_values_supported": [
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512"
      ],
      "request_object_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
        "none"
      ],
      "request_parameter_supported": true,
      "request_uri_parameter_supported": true,
      "require_pushed_authorization_requests": false,
      "require_request_uri_registration": true,
      "response_modes_supported": [
        "query",
        "fragment",
        "form_post",
        "query.jwt",
        "fragment.jwt",
        "form_post.jwt",
        "jwt"
      ],
      "response_types_supported": [
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
      ],
      "revocation_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/revoke",
      "revocation_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
      ],
      "revocation_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "scopes_supported": [
        "openid",
        "acr",
        "phone",
        "profile",
        "microprofile-jwt",
        "offline_access",
        "roles",
        "address",
        "basic",
        "web-origins",
        "email"
      ],
      "subject_types_supported": [
        "public",
        "pairwise"
      ],
      "tls_client_certificate_bound_access_tokens": true,
      "token_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/token",
      "token_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
      ],
      "token_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ],
      "userinfo_encryption_alg_values_supported": [
        "RSA-OAEP",
        "RSA-OAEP-256",
        "RSA1_5"
      ],
      "userinfo_encryption_enc_values_supported": [
        "A256GCM",
        "A192GCM",
        "A128GCM",
        "A128CBC-HS256",
        "A192CBC-HS384",
        "A256CBC-HS512"
      ],
      "userinfo_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/userinfo",
      "userinfo_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512",
        "none"
      ]
    },
    "https://keycloak.cfappsecurity.com/realms/master/.well-known/uma2-configuration": {
      "authorization_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/auth",
      "end_session_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/logout",
      "frontchannel_logout_session_supported": true,
      "frontchannel_logout_supported": true,
      "grant_types_supported": [
        "authorization_code",
        "implicit",
        "refresh_token",
        "password",
        "client_credentials",
        "urn:openid:params:grant-type:ciba",
        "urn:ietf:params:oauth:grant-type:device_code"
      ],
      "introspection_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/token/introspect",
      "issuer": "https://keycloak.cfappsecurity.com/realms/master",
      "jwks_uri": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/certs",
      "permission_endpoint": "https://keycloak.cfappsecurity.com/realms/master/authz/protection/permission",
      "policy_endpoint": "https://keycloak.cfappsecurity.com/realms/master/authz/protection/uma-policy",
      "registration_endpoint": "https://keycloak.cfappsecurity.com/realms/master/clients-registrations/openid-connect",
      "resource_registration_endpoint": "https://keycloak.cfappsecurity.com/realms/master/authz/protection/resource_set",
      "response_modes_supported": [
        "query",
        "fragment",
        "form_post",
        "query.jwt",
        "fragment.jwt",
        "form_post.jwt",
        "jwt"
      ],
      "response_types_supported": [
        "code",
        "none",
        "id_token",
        "token",
        "id_token token",
        "code id_token",
        "code token",
        "code id_token token"
      ],
      "scopes_supported": [
        "openid",
        "acr",
        "phone",
        "profile",
        "microprofile-jwt",
        "offline_access",
        "roles",
        "address",
        "basic",
        "web-origins",
        "email"
      ],
      "token_endpoint": "https://keycloak.cfappsecurity.com/realms/master/protocol/openid-connect/token",
      "token_endpoint_auth_methods_supported": [
        "private_key_jwt",
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "client_secret_jwt"
      ],
      "token_endpoint_auth_signing_alg_values_supported": [
        "PS384",
        "RS384",
        "EdDSA",
        "ES384",
        "HS256",
        "HS512",
        "ES256",
        "RS256",
        "HS384",
        "ES512",
        "PS256",
        "PS512",
        "RS512"
      ]
    }
  },
  "realm_info": {},
  "realms": []
}
	```

	## Audit Findings
	```
	[
  {
    "id": "missing_csp",
    "remediation": "Configure reverse proxy or Keycloak to set a strict CSP.",
    "severity": "low",
    "title": "Missing Content-Security-Policy header"
  },
  {
    "id": "admin_console_exposed",
    "remediation": "Restrict access to admin console via network/policy.",
    "severity": "info",
    "title": "Admin console accessible"
  }
]
	```

	## Nuclei Findings
	```
	[
  {
    "id": "nuclei_missing",
    "info": {
      "name": "Nuclei binary not found"
    },
    "severity": "info"
  }
]
	```

	## Exploitation
	```
	[]
	```
	