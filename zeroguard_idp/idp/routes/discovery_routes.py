"""
OIDC Discovery (OpenID Connect Discovery 1.0)
/.well-known/openid-configuration  — discovery document
/.well-known/jwks.json             — public RSA keys
"""
from flask import Blueprint, jsonify
from idp.utils.key_manager import get_jwks

discovery_bp = Blueprint('discovery', __name__)

ISSUER = "http://localhost:5008"  # Must match the actual URL where this IDP is hosted

@discovery_bp.route('/.well-known/openid-configuration')
def openid_configuration():
    """OIDC Discovery Document — clients use this to auto-configure."""
    return jsonify({
        "issuer":                  ISSUER,
        "authorization_endpoint":  f"{ISSUER}/oauth/authorize",
        "token_endpoint":          f"{ISSUER}/oauth/token",
        "userinfo_endpoint":       f"{ISSUER}/oauth/userinfo",
        "revocation_endpoint":     f"{ISSUER}/oauth/revoke",
        "introspection_endpoint":  f"{ISSUER}/oauth/introspect",
        "end_session_endpoint":    f"{ISSUER}/oauth/logout",
        "jwks_uri":                f"{ISSUER}/.well-known/jwks.json",
        "response_types_supported":          ["code"],
        "grant_types_supported":             ["authorization_code", "refresh_token"],
        "subject_types_supported":           ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported":        ["openid", "profile", "email", "roles"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported":        ["sub", "iss", "aud", "exp", "iat", "email", "role", "nonce"],
        "code_challenge_methods_supported":  ["S256"],
    }), 200, {'Content-Type': 'application/json'}


@discovery_bp.route('/.well-known/jwks.json')
def jwks():
    """Public RSA key — clients use this to verify RS256 JWT signatures."""
    return jsonify(get_jwks()), 200, {'Content-Type': 'application/json'}
