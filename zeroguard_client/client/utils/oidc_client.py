"""
OAuth2 / OIDC Client Helper
----------------------------
Handles the client side of the Authorization Code + PKCE flow:
  - generate_pkce()          build code_verifier + code_challenge (RFC 7636)
  - build_authorize_url()    construct IDP redirect URL
  - exchange_code()          POST to /oauth/token
  - validate_id_token()      verify RS256 signature using IDP's JWKS
  - fetch_jwks()             GET /.well-known/jwks.json (cached)
  - refresh_access_token()   POST to /oauth/token with refresh_token
  - revoke_token()           POST to /oauth/revoke
"""
import os, hashlib, secrets, base64, time
import requests
import jwt as pyjwt
from dotenv import load_dotenv

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
load_dotenv(os.path.join(_BASE_DIR, '.env'), override=True)

IDP_BASE    = os.getenv('IDP_BASE_URL',  'http://localhost:5000')
CLIENT_ID   = os.getenv('CLIENT_ID',     'zeroguard-client')
CLIENT_SECRET = os.getenv('CLIENT_SECRET', '')
REDIRECT_URI  = os.getenv('REDIRECT_URI', 'http://localhost:5001/callback')

# JWKS cache — refresh every 5 minutes
_jwks_cache      = None
_jwks_fetched_at = 0
_JWKS_TTL        = 300   # seconds


# ── PKCE (RFC 7636) ────────────────────────────────────────────────

def generate_pkce() -> dict:
    """Generate code_verifier and S256 code_challenge."""
    code_verifier  = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
    digest         = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return {'code_verifier': code_verifier, 'code_challenge': code_challenge}


# ── Authorization URL ──────────────────────────────────────────────

def build_authorize_url(state: str, code_challenge: str, nonce: str) -> str:
    from urllib.parse import urlencode
    params = {
        'response_type':         'code',
        'client_id':             CLIENT_ID,
        'redirect_uri':          REDIRECT_URI,
        'scope':                 'openid profile email roles',
        'state':                 state,
        'code_challenge':        code_challenge,
        'code_challenge_method': 'S256',
        'nonce':                 nonce,
    }
    return f"{IDP_BASE}/oauth/authorize?{urlencode(params)}"


# ── Token Exchange ─────────────────────────────────────────────────

def exchange_code(code: str, code_verifier: str) -> dict:
    """Exchange auth code + PKCE verifier for tokens."""
    resp = requests.post(
        f"{IDP_BASE}/oauth/token",
        data={
            'grant_type':    'authorization_code',
            'code':          code,
            'redirect_uri':  REDIRECT_URI,
            'client_id':     CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'code_verifier': code_verifier,
        },
        timeout=10
    )
    resp.raise_for_status()
    return resp.json()


def refresh_access_token(refresh_token: str) -> dict:
    resp = requests.post(
        f"{IDP_BASE}/oauth/token",
        data={
            'grant_type':    'refresh_token',
            'refresh_token': refresh_token,
            'client_id':     CLIENT_ID,
            'client_secret': CLIENT_SECRET,
        },
        timeout=10
    )
    resp.raise_for_status()
    return resp.json()


def revoke_token(token: str, token_type_hint: str = 'access_token'):
    requests.post(
        f"{IDP_BASE}/oauth/revoke",
        data={
            'token':            token,
            'token_type_hint':  token_type_hint,
            'client_id':        CLIENT_ID,
            'client_secret':    CLIENT_SECRET,
        },
        timeout=10
    )


# ── JWKS + ID Token Validation ─────────────────────────────────────

def fetch_jwks() -> list:
    """Fetch IDP's public keys — cached for 5 minutes."""
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache
    resp = requests.get(f"{IDP_BASE}/.well-known/jwks.json", timeout=10)
    resp.raise_for_status()
    _jwks_cache      = resp.json().get('keys', [])
    _jwks_fetched_at = now
    return _jwks_cache


def _jwk_to_public_key(jwk: dict):
    """Convert a JWK RSA key dict to a cryptography public key object."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend

    def _b64_to_int(b64: str) -> int:
        padded = b64 + '=' * (4 - len(b64) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), 'big')

    n = _b64_to_int(jwk['n'])
    e = _b64_to_int(jwk['e'])
    return RSAPublicNumbers(e, n).public_key(default_backend())


def validate_id_token(id_token: str, nonce: str = None) -> dict:
    """
    Validate RS256 ID token using IDP's public JWKS.
    Verifies: signature, issuer, audience, expiry, nonce.
    """
    # Decode header to get kid
    unverified_header = pyjwt.get_unverified_header(id_token)
    kid = unverified_header.get('kid')

    # Find matching key in JWKS
    keys = fetch_jwks()
    jwk  = next((k for k in keys if k.get('kid') == kid), None)
    if not jwk and keys:
        jwk = keys[0]   # fallback to first key if kid not found
    if not jwk:
        raise ValueError("No matching JWK found for ID token")

    pub_key = _jwk_to_public_key(jwk)

    payload = pyjwt.decode(
        id_token,
        pub_key,
        algorithms=['RS256'],
        audience=CLIENT_ID,
        issuer=IDP_BASE,
    )

    # Nonce check (OIDC replay protection)
    if nonce and payload.get('nonce') != nonce:
        raise ValueError("Nonce mismatch — possible replay attack")

    return payload


def validate_access_token(access_token: str) -> dict:
    """Validate access token using IDP's JWKS — used by client middleware."""
    keys = fetch_jwks()
    if not keys:
        raise ValueError("Could not fetch JWKS from IDP")

    unverified_header = pyjwt.get_unverified_header(access_token)
    kid = unverified_header.get('kid')
    jwk = next((k for k in keys if k.get('kid') == kid), keys[0])
    pub_key = _jwk_to_public_key(jwk)

    return pyjwt.decode(
        access_token,
        pub_key,
        algorithms=['RS256'],
        audience=CLIENT_ID,
        issuer=IDP_BASE,
    )
