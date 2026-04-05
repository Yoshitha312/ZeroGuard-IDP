import os, hashlib, secrets, base64, time
from datetime import timedelta
import requests
import jwt as pyjwt
from dotenv import load_dotenv

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
load_dotenv(os.path.join(_BASE_DIR, '.env'), override=True)


def _get_idp_base():
    load_dotenv(os.path.join(_BASE_DIR, '.env'), override=True)
    return os.getenv('IDP_BASE_URL', 'http://localhost:5008').rstrip('/')

def _get_client_id():
    return os.getenv('CLIENT_ID', 'zeroguard-client')

def _get_client_secret():
    return os.getenv('CLIENT_SECRET', '')

def _get_redirect_uri():
    return os.getenv('REDIRECT_URI', 'http://localhost:5001/callback')

# JWKS cache
_jwks_cache      = None
_jwks_fetched_at = 0
_JWKS_TTL        = 300


def generate_pkce() -> dict:
    code_verifier  = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode()
    digest         = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    return {'code_verifier': code_verifier, 'code_challenge': code_challenge}


def build_authorize_url(state: str, code_challenge: str, nonce: str) -> str:
    from urllib.parse import urlencode
    idp = _get_idp_base()
    params = {
        'response_type':         'code',
        'client_id':             _get_client_id(),
        'redirect_uri':          _get_redirect_uri(),
        'scope':                 'openid profile email roles',
        'state':                 state,
        'code_challenge':        code_challenge,
        'code_challenge_method': 'S256',
        'nonce':                 nonce,
    }
    return f"{idp}/oauth/authorize?{urlencode(params)}"


def exchange_code(code: str, code_verifier: str) -> dict:
    idp = _get_idp_base()
    resp = requests.post(
        f"{idp}/oauth/token",
        data={
            'grant_type':    'authorization_code',
            'code':          code,
            'redirect_uri':  _get_redirect_uri(),
            'client_id':     _get_client_id(),
            'client_secret': _get_client_secret(),
            'code_verifier': code_verifier,
        },
        timeout=15
    )
    if not resp.ok:
        raise Exception(f"IDP token endpoint returned {resp.status_code}: {resp.text[:300]}")
    return resp.json()


def refresh_access_token(refresh_token: str) -> dict:
    idp = _get_idp_base()
    resp = requests.post(
        f"{idp}/oauth/token",
        data={
            'grant_type':    'refresh_token',
            'refresh_token': refresh_token,
            'client_id':     _get_client_id(),
            'client_secret': _get_client_secret(),
        },
        timeout=15
    )
    resp.raise_for_status()
    return resp.json()


def revoke_token(token: str, token_type_hint: str = 'access_token'):
    idp = _get_idp_base()
    try:
        requests.post(
            f"{idp}/oauth/revoke",
            data={
                'token':           token,
                'token_type_hint': token_type_hint,
                'client_id':       _get_client_id(),
                'client_secret':   _get_client_secret(),
            },
            timeout=10
        )
    except Exception:
        pass


def fetch_jwks() -> list:
    global _jwks_cache, _jwks_fetched_at
    now = time.time()
    if _jwks_cache and (now - _jwks_fetched_at) < _JWKS_TTL:
        return _jwks_cache
    idp  = _get_idp_base()
    resp = requests.get(f"{idp}/.well-known/jwks.json", timeout=10)
    resp.raise_for_status()
    _jwks_cache      = resp.json().get('keys', [])
    _jwks_fetched_at = now
    print(f"[OIDC] Fetched JWKS from {idp} — {len(_jwks_cache)} key(s)")
    return _jwks_cache


def _force_refresh_jwks() -> list:
    global _jwks_cache, _jwks_fetched_at
    _jwks_cache      = None
    _jwks_fetched_at = 0
    return fetch_jwks()


def _jwk_to_public_key(jwk: dict):
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.backends import default_backend

    def _b64_to_int(b64: str) -> int:
        padded = b64 + '=' * (4 - len(b64) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), 'big')

    n = _b64_to_int(jwk['n'])
    e = _b64_to_int(jwk['e'])
    return RSAPublicNumbers(e, n).public_key(default_backend())


def _pick_jwk(keys: list, kid: str):
    """Pick key by kid, fallback to first key, force-refresh if still no match."""
    jwk = next((k for k in keys if k.get('kid') == kid), None)
    if not jwk:
        keys = _force_refresh_jwks()
        jwk  = next((k for k in keys if k.get('kid') == kid), keys[0] if keys else None)
    return jwk


def validate_id_token(id_token: str, nonce: str = None) -> dict:
    """
    Validate RS256 ID token using IDP's JWKS.
    issuer validated against IDP_BASE_URL — must match token_service.py get_issuer().
    leeway=300s handles clock drift and slow TOTP entry on localhost.
    """
    idp = _get_idp_base()

    unverified_header = pyjwt.get_unverified_header(id_token)
    kid  = unverified_header.get('kid')
    keys = fetch_jwks()
    jwk  = _pick_jwk(keys, kid)

    if not jwk:
        raise ValueError("No JWK found — is the IDP running?")

    pub_key = _jwk_to_public_key(jwk)

    payload = pyjwt.decode(
        id_token,
        pub_key,
        algorithms=['RS256'],
        audience=_get_client_id(),
        issuer=idp,                      # matches token_service.get_issuer() = IDP_BASE_URL
        leeway=timedelta(seconds=300),
    )

    if nonce and payload.get('nonce') != nonce:
        raise ValueError(
            f"Nonce mismatch: expected {nonce[:8]}... got {str(payload.get('nonce',''))[:8]}..."
        )

    return payload


def validate_access_token(access_token: str) -> dict:
    """Validate access token using IDP's JWKS — used by client middleware."""
    idp  = _get_idp_base()
    keys = fetch_jwks()
    if not keys:
        raise ValueError("Could not fetch JWKS from IDP — is IDP running?")

    unverified_header = pyjwt.get_unverified_header(access_token)
    kid = unverified_header.get('kid')
    jwk = _pick_jwk(keys, kid)
    pub_key = _jwk_to_public_key(jwk)

    return pyjwt.decode(
        access_token,
        pub_key,
        algorithms=['RS256'],
        audience=_get_client_id(),
        issuer=idp,
        leeway=timedelta(seconds=300),
    )
