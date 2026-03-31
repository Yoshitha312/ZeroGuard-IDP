"""
Token Service
------------
Issues RS256-signed JWTs following OIDC Core spec.
Access Token  — 15 min, verifiable by any client with JWKS
ID Token      — OIDC claims: sub, iss, aud, iat, exp, nonce, email, role
Refresh Token — long-lived opaque reference token
"""
import os
import uuid
import secrets
from datetime import datetime, timedelta
import jwt as pyjwt

from idp.utils.key_manager import get_private_key_pem, get_kid
from idp.extensions import db

ISSUER = "http://localhost:5008"  # Must match the actual URL where this IDP is hosted


def _get_expiry(minutes=None, days=None):
    if minutes:
        return datetime.utcnow() + timedelta(minutes=minutes)
    return datetime.utcnow() + timedelta(days=days)


def issue_tokens(user, client_id: str, scope: str, nonce: str = None) -> dict:
    """Issue access token, ID token, and refresh token."""
    from idp.models.models import TokenRecord

    access_minutes  = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', 15))
    refresh_days    = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS', 7))

    now = datetime.utcnow()
    private_key = get_private_key_pem()
    kid = get_kid()

    # ── Access Token ───────────────────────────────────────────────
    access_jti = str(uuid.uuid4())
    access_exp = now + timedelta(minutes=access_minutes)
    access_payload = {
        'iss':   ISSUER,
        'sub':   str(user.id),
        'aud':   client_id,
        'iat':   int(now.timestamp()),
        'exp':   int(access_exp.timestamp()),
        'jti':   access_jti,
        'email': user.email,
        'role':  user.role,
        'scope': scope,
    }
    access_token = pyjwt.encode(
        access_payload,
        private_key,
        algorithm='RS256',
        headers={'kid': kid}
    )

    # ── ID Token (OIDC) ────────────────────────────────────────────
    id_jti = str(uuid.uuid4())
    id_exp = now + timedelta(minutes=access_minutes)
    id_payload = {
        'iss':   ISSUER,
        'sub':   str(user.id),
        'aud':   client_id,
        'iat':   int(now.timestamp()),
        'exp':   int(id_exp.timestamp()),
        'jti':   id_jti,
        'email': user.email,
        'role':  user.role,
    }
    if nonce:
        id_payload['nonce'] = nonce
    id_token = pyjwt.encode(
        id_payload,
        private_key,
        algorithm='RS256',
        headers={'kid': kid}
    )

    # ── Refresh Token (opaque reference) ──────────────────────────
    refresh_jti   = str(uuid.uuid4())
    refresh_token = secrets.token_urlsafe(48)
    refresh_exp   = now + timedelta(days=refresh_days)

    # ── Persist token records ──────────────────────────────────────
    db.session.add(TokenRecord(jti=access_jti,  token_type='access',  user_id=user.id, client_id=client_id, expires_at=access_exp))
    db.session.add(TokenRecord(jti=id_jti,      token_type='id',      user_id=user.id, client_id=client_id, expires_at=id_exp))
    db.session.add(TokenRecord(jti=refresh_jti, token_type='refresh', user_id=user.id, client_id=client_id, expires_at=refresh_exp))
    db.session.commit()

    # Store refresh token → jti mapping so we can revoke it
    import flask
    flask.current_app.config.setdefault('REFRESH_TOKEN_MAP', {})[refresh_token] = refresh_jti

    return {
        'access_token':  access_token,
        'id_token':      id_token,
        'refresh_token': refresh_token,
        'token_type':    'Bearer',
        'expires_in':    access_minutes * 60,
        'scope':         scope,
    }


def revoke_token_by_jti(jti: str):
    from idp.models.models import TokenRecord
    record = TokenRecord.query.filter_by(jti=jti).first()
    if record:
        record.revoked = True
        db.session.commit()


def decode_access_token(token: str, client_id: str) -> dict:
    """Verify and decode an RS256 access token — used by introspect endpoint."""
    from idp.utils.key_manager import get_public_key_pem
    from idp.models.models import TokenRecord
    pub = get_public_key_pem()
    payload = pyjwt.decode(
        token,
        pub,
        algorithms=['RS256'],
        audience=client_id,
        issuer=ISSUER
    )
    if TokenRecord.is_revoked(payload['jti']):
        raise Exception("Token has been revoked")
    return payload
