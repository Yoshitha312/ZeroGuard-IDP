"""
OIDC Discovery Routes
FIX: get_issuer() now reads IDP_BASE_URL instead of constructing from PORT.
This keeps issuer identical across token_service, discovery, and oidc_client.
"""
import os
from flask import Blueprint, jsonify
from idp.utils.key_manager import get_jwks

discovery_bp = Blueprint('discovery', __name__)


def get_issuer():
    """Same logic as token_service.get_issuer() — must stay in sync."""
    return os.getenv('IDP_BASE_URL', 'http://localhost:5008').rstrip('/')


@discovery_bp.route('/.well-known/openid-configuration')
def openid_configuration():
    issuer = get_issuer()
    return jsonify({
        "issuer":                                issuer,
        "authorization_endpoint":               f"{issuer}/oauth/authorize",
        "token_endpoint":                        f"{issuer}/oauth/token",
        "userinfo_endpoint":                     f"{issuer}/oauth/userinfo",
        "revocation_endpoint":                   f"{issuer}/oauth/revoke",
        "introspection_endpoint":                f"{issuer}/oauth/introspect",
        "end_session_endpoint":                  f"{issuer}/oauth/logout",
        "jwks_uri":                              f"{issuer}/.well-known/jwks.json",
        "response_types_supported":              ["code"],
        "grant_types_supported":                 ["authorization_code", "refresh_token"],
        "subject_types_supported":               ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported":                      ["openid", "profile", "email", "roles"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported":                      ["sub", "iss", "aud", "exp", "iat",
                                                  "email", "role", "nonce"],
        "code_challenge_methods_supported":      ["S256"],
    }), 200, {'Content-Type': 'application/json'}


@discovery_bp.route('/.well-known/jwks.json')
def jwks():
    return jsonify(get_jwks()), 200, {'Content-Type': 'application/json'}
