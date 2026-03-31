"""
RSA Key Manager
--------------
Generates and persists an RSA-2048 key pair used for RS256 JWT signing.
The public key is exposed via /.well-known/jwks.json so any client
can verify tokens without a shared secret — proper OIDC standard.
"""
import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_KEY_DIR  = os.path.join(_BASE_DIR, 'keys')
_PRIV_PATH = os.path.join(_KEY_DIR, 'private.pem')
_PUB_PATH  = os.path.join(_KEY_DIR, 'public.pem')

_private_key = None
_public_key  = None


def _ensure_keys():
    global _private_key, _public_key
    if _private_key and _public_key:
        return

    os.makedirs(_KEY_DIR, exist_ok=True)

    if os.path.exists(_PRIV_PATH) and os.path.exists(_PUB_PATH):
        with open(_PRIV_PATH, 'rb') as f:
            _private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(_PUB_PATH, 'rb') as f:
            _public_key = serialization.load_pem_public_key(f.read())
        print("[IDP] RSA keys loaded from disk.")
    else:
        print("[IDP] Generating new RSA-2048 key pair...")
        _private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        _public_key = _private_key.public_key()

        with open(_PRIV_PATH, 'wb') as f:
            f.write(_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(_PUB_PATH, 'wb') as f:
            f.write(_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("[IDP] RSA key pair generated and saved.")


def get_private_key_pem() -> str:
    _ensure_keys()
    return _private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()


def get_public_key_pem() -> str:
    _ensure_keys()
    return _public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def get_jwks() -> dict:
    """Return JWKS (JSON Web Key Set) for the /.well-known/jwks.json endpoint."""
    _ensure_keys()
    pub_numbers = _public_key.public_key().public_numbers() \
        if hasattr(_public_key, 'public_key') else _public_key.public_numbers()

    def _int_to_base64url(n):
        byte_length = (n.bit_length() + 7) // 8
        b = n.to_bytes(byte_length, 'big')
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

    # Compute key ID (kid) from public key fingerprint
    pub_pem = get_public_key_pem().encode()
    kid = hashlib.sha256(pub_pem).hexdigest()[:16]

    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n":   _int_to_base64url(pub_numbers.n),
            "e":   _int_to_base64url(pub_numbers.e),
        }]
    }


def get_kid() -> str:
    _ensure_keys()
    pub_pem = get_public_key_pem().encode()
    return hashlib.sha256(pub_pem).hexdigest()[:16]
