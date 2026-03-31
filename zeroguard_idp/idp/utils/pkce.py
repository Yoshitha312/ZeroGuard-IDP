"""
PKCE Utilities (RFC 7636)
Proof Key for Code Exchange — prevents auth code interception attacks.
"""
import hashlib, base64, re

def verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """
    Verify code_verifier against stored code_challenge.
    S256: BASE64URL(SHA256(code_verifier)) == code_challenge
    """
    if not code_verifier or not code_challenge:
        return False
    if method == 'S256':
        digest   = hashlib.sha256(code_verifier.encode('ascii')).digest()
        computed = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')
        return computed == code_challenge
    # plain (not recommended but supported)
    if method == 'plain':
        return code_verifier == code_challenge
    return False

def is_valid_code_verifier(verifier: str) -> bool:
    """RFC 7636 §4.1: 43-128 chars, [A-Z a-z 0-9 - . _ ~]"""
    if not verifier:
        return False
    return bool(re.match(r'^[A-Za-z0-9\-._~]{43,128}$', verifier))
