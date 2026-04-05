"""
RSA Key Manager — Fixed
-----------------------
FIX: Keys were being regenerated on every Flask worker process startup
because _private_key/_public_key globals are per-process and start as None.
Flask debug mode spawns multiple processes; each one called _ensure_keys()
and if the timing was wrong, both tried to write new keys simultaneously.

Fix strategy:
1. Load keys EAGERLY at module import time (not lazily on first request)
2. Use a file lock to prevent two processes writing keys simultaneously  
3. Re-read from disk after acquiring lock in case another process wrote first
"""
import os
import base64
import hashlib
import threading
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Keys live inside idp/keys/ — _BASE_DIR is the idp/ package directory
_BASE_DIR  = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
_KEY_DIR   = os.path.join(_BASE_DIR, 'keys')
_PRIV_PATH = os.path.join(_KEY_DIR, 'private.pem')
_PUB_PATH  = os.path.join(_KEY_DIR, 'public.pem')
_LOCK_PATH = os.path.join(_KEY_DIR, '.keygen.lock')

_private_key = None
_public_key  = None
_thread_lock = threading.Lock()


def _load_or_generate():
    """Load keys from disk or generate new ones. Thread + process safe."""
    global _private_key, _public_key

    os.makedirs(_KEY_DIR, exist_ok=True)

    # Use a simple file-based lock for cross-process safety
    import fcntl
    lock_fd = open(_LOCK_PATH, 'w')
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)  # exclusive lock — blocks other processes

        # Re-check after acquiring lock (another process may have written keys)
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
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        lock_fd.close()


# ── Eager load at import time ──────────────────────────────────────
# This runs when Python first imports this module — before any request.
# Every Flask worker process imports this module, so every process gets
# the keys immediately. No lazy loading = no race condition.
with _thread_lock:
    _load_or_generate()


def _ensure_keys():
    """Kept for compatibility — keys are already loaded at import time."""
    global _private_key, _public_key
    if not _private_key or not _public_key:
        with _thread_lock:
            _load_or_generate()


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
    """Return JWKS for /.well-known/jwks.json endpoint."""
    _ensure_keys()
    pub_numbers = _public_key.public_numbers()

    def _int_to_base64url(n):
        byte_length = (n.bit_length() + 7) // 8
        b = n.to_bytes(byte_length, 'big')
        return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

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