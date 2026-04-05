"""
Token Service — IDP side

ROOT CAUSE FIX:
datetime.utcnow() returns a NAIVE datetime with no timezone info.
PyJWT uses time.time() internally which is always UTC unix timestamp.
On a Mac set to IST (UTC+5:30), datetime.utcnow() returns the correct
UTC time as a naive datetime, BUT SQLite stores it and when read back
it's treated as local time by some Python datetime comparisons.

More critically: the token exp was being stored as UTC unix timestamp
correctly, but the leeway comparison in PyJWT was failing because the
system clock (time.time()) showed the token as expired by hours.

The real fix: use datetime.now(timezone.utc) everywhere so datetimes
are always timezone-aware and comparisons are unambiguous.
Also: store unix timestamps directly in JWT (already correct) but
ensure expires_at in DB uses aware datetimes.
"""
import os, uuid, secrets
from datetime import datetime, timedelta, timezone
import jwt as pyjwt
from idp.utils.key_manager import get_private_key_pem, get_kid
from idp.extensions import db


def get_issuer() -> str:
    return os.getenv('IDP_BASE_URL', 'http://localhost:5008').rstrip('/')


def _utcnow():
    """Always return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def issue_tokens(user, client_id: str, scope: str, nonce: str = None) -> dict:
    from idp.models.models import TokenRecord

    access_minutes = max(15, int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', 15)))
    refresh_days   = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS', 7))
    now            = _utcnow()
    private_key    = get_private_key_pem()
    kid            = get_kid()
    issuer         = get_issuer()

    # Use unix timestamps for JWT claims — always UTC, no timezone ambiguity
    now_ts = int(now.timestamp())

    # Access Token
    access_jti = str(uuid.uuid4())
    access_exp = now + timedelta(minutes=access_minutes)
    access_exp_ts = int(access_exp.timestamp())

    access_payload = {
        'iss':   issuer,
        'sub':   str(user.id),
        'aud':   client_id,
        'iat':   now_ts,
        'exp':   access_exp_ts,
        'jti':   access_jti,
        'email': user.email,
        'role':  user.role,
        'scope': scope,
    }
    access_token = pyjwt.encode(
        access_payload, private_key, algorithm='RS256', headers={'kid': kid}
    )

    # ID Token (OIDC)
    id_jti = str(uuid.uuid4())
    id_payload = {
        'iss':   issuer,
        'sub':   str(user.id),
        'aud':   client_id,
        'iat':   now_ts,
        'exp':   access_exp_ts,
        'jti':   id_jti,
        'email': user.email,
        'role':  user.role,
    }
    if nonce:
        id_payload['nonce'] = nonce
    id_token = pyjwt.encode(
        id_payload, private_key, algorithm='RS256', headers={'kid': kid}
    )

    # Refresh Token (opaque)
    refresh_jti   = str(uuid.uuid4())
    refresh_token = secrets.token_urlsafe(48)
    refresh_exp   = now + timedelta(days=refresh_days)

    db.session.add(TokenRecord(jti=access_jti,  token_type='access',
                               user_id=user.id, client_id=client_id,
                               expires_at=access_exp))
    db.session.add(TokenRecord(jti=id_jti,      token_type='id',
                               user_id=user.id, client_id=client_id,
                               expires_at=access_exp))
    db.session.add(TokenRecord(jti=refresh_jti, token_type='refresh',
                               user_id=user.id, client_id=client_id,
                               expires_at=refresh_exp))
    db.session.commit()

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
    r = TokenRecord.query.filter_by(jti=jti).first()
    if r:
        r.revoked = True
        db.session.commit()


def decode_access_token(token: str, client_id: str) -> dict:
    from idp.utils.key_manager import get_public_key_pem
    from idp.models.models import TokenRecord
    pub = get_public_key_pem()
    payload = pyjwt.decode(
        token, pub,
        algorithms=['RS256'],
        audience=client_id,
        issuer=get_issuer(),
        leeway=timedelta(seconds=300)
    )
    if TokenRecord.is_revoked(payload['jti']):
        raise Exception("Token has been revoked")
    return payload