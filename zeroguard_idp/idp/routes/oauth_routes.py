"""
OAuth 2.0 + OIDC Routes
-----------------------
/oauth/authorize   — Authorization endpoint (RFC 6749 §3.1)
/oauth/token       — Token endpoint (RFC 6749 §3.2)
/oauth/revoke      — Token revocation (RFC 7009)
/oauth/introspect  — Token introspection (RFC 7662)
/oauth/userinfo    — OIDC UserInfo endpoint
/oauth/logout      — OIDC end-session (SSO logout)
"""
import os, secrets
from datetime import datetime, timedelta
from urllib.parse import urlencode
from flask import Blueprint, request, jsonify, redirect, session, url_for, render_template, current_app

from idp.extensions import db, limiter
from idp.models.models import OAuthClient, AuthorizationCode, User, TokenRecord, SSOSession
from idp.utils.pkce import verify_pkce
from idp.utils.token_service import issue_tokens, decode_access_token, revoke_token_by_jti
from idp.utils.logger import log_event

oauth_bp = Blueprint('oauth', __name__, url_prefix='/oauth')

# ── Helpers ────────────────────────────────────────────────────────────────────

def _error_redirect(redirect_uri, error, error_description, state=None):
    params = {'error': error, 'error_description': error_description}
    if state:
        params['state'] = state
    return redirect(f"{redirect_uri}?{urlencode(params)}")

def _json_error(code, error, description):
    return jsonify({'error': error, 'error_description': description}), code

def _get_sso_user():
    """Return User if a valid SSO session cookie exists."""
    sid = session.get('sso_session_id')
    if not sid:
        return None
    sso = SSOSession.query.filter_by(session_id=sid, is_active=True).first()
    if sso and sso.is_valid():
        return sso.user
    return None

# ── Authorization Endpoint ─────────────────────────────────────────────────────

@oauth_bp.route('/authorize', methods=['GET', 'POST'])
def authorize():
    # Validate required params
    client_id     = request.values.get('client_id', '').strip()
    redirect_uri  = request.values.get('redirect_uri', '').strip()
    response_type = request.values.get('response_type', '').strip()
    scope         = request.values.get('scope', 'openid').strip()
    state         = request.values.get('state', '')
    code_challenge        = request.values.get('code_challenge', '').strip()
    code_challenge_method = request.values.get('code_challenge_method', 'S256').strip()
    nonce         = request.values.get('nonce', '').strip()

    # Validate client
    client = OAuthClient.query.filter_by(client_id=client_id, is_active=True).first()
    if not client:
        return _json_error(400, 'invalid_client', 'Unknown client_id')

    if not client.has_redirect_uri(redirect_uri):
        return _json_error(400, 'invalid_request', 'redirect_uri not registered')

    if response_type != 'code':
        return _error_redirect(redirect_uri, 'unsupported_response_type',
                               'Only authorization_code flow supported', state)

    if not code_challenge:
        return _error_redirect(redirect_uri, 'invalid_request',
                               'code_challenge required (PKCE mandatory)', state)

    # SSO — skip login if valid session exists
    sso_user = _get_sso_user()

    if request.method == 'GET':
        if sso_user:
            # SSO hit — auto-issue code without login prompt
            return _issue_code(sso_user, client_id, redirect_uri, scope, state,
                               code_challenge, code_challenge_method, nonce)
        # Show login page, pass all OAuth params through hidden fields
        return render_template('idp_login.html',
            client_name=client.client_name,
            params=request.args.to_dict()
        )

    # POST — process login form
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()
    totp_code= request.form.get('totp_code', '').strip()
    step     = request.form.get('step', 'credentials')

    # Carry all OAuth params from form
    oauth_params = {k: v for k, v in request.form.items()
                    if k in ('client_id','redirect_uri','response_type','scope',
                             'state','code_challenge','code_challenge_method','nonce')}

    import bcrypt
    user = User.query.filter_by(email=email, is_active=True).first()

    if step == 'credentials':
        if not user:
            return render_template('idp_login.html', error='Invalid credentials',
                                   client_name=client.client_name, params=oauth_params)

        # Lockout check
        if user.lockout_until and user.lockout_until > datetime.utcnow():
            mins = int((user.lockout_until - datetime.utcnow()).total_seconds() / 60) + 1
            log_event('LOGIN_BLOCKED', user_id=user.id, client_id=client_id, severity='warning')
            return render_template('idp_login.html',
                                   error=f'Account locked. Try again in {mins} min.',
                                   client_name=client.client_name, params=oauth_params)

        if not bcrypt.checkpw(password.encode(), user.hashed_password.encode()):
            user.failed_attempts += 1
            max_attempts = int(os.getenv('MAX_FAILED_ATTEMPTS', 5))
            lockout_mins = int(os.getenv('LOCKOUT_DURATION_MINUTES', 15))
            if user.failed_attempts >= max_attempts:
                user.lockout_until = datetime.utcnow() + timedelta(minutes=lockout_mins)
                log_event('ACCOUNT_LOCKED', user_id=user.id, client_id=client_id, severity='critical')
            db.session.commit()
            log_event('LOGIN_FAILED', user_id=user.id, client_id=client_id, severity='warning')
            return render_template('idp_login.html', error='Invalid credentials',
                                   client_name=client.client_name, params=oauth_params)

        user.failed_attempts = 0
        db.session.commit()
        # Ask for TOTP
        oauth_params['email'] = email
        return render_template('idp_totp.html',
                               client_name=client.client_name, params=oauth_params)

    elif step == 'totp':
        from idp.utils.totp_utils import verify_totp
        if not user or not verify_totp(user.totp_secret_encrypted, totp_code):
            log_event('TOTP_FAILED', user_id=user.id if user else None, client_id=client_id, severity='warning')
            oauth_params['email'] = email
            return render_template('idp_totp.html', error='Invalid TOTP code',
                                   client_name=client.client_name, params=oauth_params)

        # ✅ Authenticated — create SSO session
        _create_sso_session(user)
        log_event('LOGIN_SUCCESS', user_id=user.id, client_id=client_id)
        return _issue_code(user, client_id, redirect_uri, scope, state,
                           code_challenge, code_challenge_method, nonce)

    return _json_error(400, 'invalid_request', 'Unknown step')


def _create_sso_session(user):
    sid = secrets.token_urlsafe(48)
    sso = SSOSession(
        session_id=sid,
        user_id=user.id,
        expires_at=datetime.utcnow() + timedelta(hours=8)
    )
    db.session.add(sso)
    db.session.commit()
    session['sso_session_id'] = sid


def _issue_code(user, client_id, redirect_uri, scope, state,
                code_challenge, code_challenge_method, nonce):
    code = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(
        minutes=int(os.getenv('AUTH_CODE_EXPIRE_MINUTES', 10))
    )
    auth_code = AuthorizationCode(
        code=code, client_id=client_id, user_id=user.id,
        redirect_uri=redirect_uri, scope=scope,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce, expires_at=expires_at
    )
    db.session.add(auth_code)
    db.session.commit()
    log_event('AUTH_CODE_ISSUED', user_id=user.id, client_id=client_id)

    params = {'code': code}
    if state:
        params['state'] = state
    return redirect(f"{redirect_uri}?{urlencode(params)}")


# ── Token Endpoint ─────────────────────────────────────────────────────────────

@oauth_bp.route('/token', methods=['POST'])
@limiter.limit("20 per minute")
def token():
    grant_type    = request.form.get('grant_type', '')
    client_id     = request.form.get('client_id', '').strip()
    client_secret = request.form.get('client_secret', '').strip()

    client = OAuthClient.query.filter_by(client_id=client_id, is_active=True).first()
    if not client or client.client_secret != client_secret:
        return _json_error(401, 'invalid_client', 'Client authentication failed')

    # ── Authorization Code Grant ───────────────────────────────────
    if grant_type == 'authorization_code':
        code          = request.form.get('code', '').strip()
        redirect_uri  = request.form.get('redirect_uri', '').strip()
        code_verifier = request.form.get('code_verifier', '').strip()

        auth_code = AuthorizationCode.query.filter_by(code=code, client_id=client_id, used=False).first()

        if not auth_code:
            return _json_error(400, 'invalid_grant', 'Authorization code not found or already used')
        if auth_code.expires_at < datetime.utcnow():
            return _json_error(400, 'invalid_grant', 'Authorization code expired')
        if auth_code.redirect_uri != redirect_uri:
            return _json_error(400, 'invalid_grant', 'redirect_uri mismatch')

        # PKCE verification (RFC 7636)
        if auth_code.code_challenge:
            if not verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
                log_event('PKCE_FAILED', client_id=client_id, severity='warning')
                return _json_error(400, 'invalid_grant', 'PKCE code_verifier verification failed')

        # Mark code as used (single-use)
        auth_code.used = True
        db.session.commit()

        user = db.session.get(User, auth_code.user_id)
        tokens = issue_tokens(user, client_id, auth_code.scope, auth_code.nonce)
        log_event('TOKENS_ISSUED', user_id=user.id, client_id=client_id)
        return jsonify(tokens), 200

    # ── Refresh Token Grant ────────────────────────────────────────
    if grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token', '').strip()
        token_map     = current_app.config.get('REFRESH_TOKEN_MAP', {})
        jti           = token_map.get(refresh_token)

        if not jti:
            return _json_error(400, 'invalid_grant', 'Invalid refresh token')

        record = TokenRecord.query.filter_by(jti=jti, token_type='refresh', revoked=False).first()
        if not record or record.expires_at < datetime.utcnow():
            return _json_error(400, 'invalid_grant', 'Refresh token expired or revoked')

        # Rotate — revoke old refresh token
        revoke_token_by_jti(jti)
        del token_map[refresh_token]

        user   = db.session.get(User, record.user_id)
        tokens = issue_tokens(user, client_id, 'openid profile email')
        log_event('TOKEN_REFRESHED', user_id=user.id, client_id=client_id)
        return jsonify(tokens), 200

    return _json_error(400, 'unsupported_grant_type', f'Grant type {grant_type!r} not supported')


# ── Revocation Endpoint (RFC 7009) ─────────────────────────────────────────────

@oauth_bp.route('/revoke', methods=['POST'])
def revoke():
    token_hint = request.form.get('token_type_hint', 'access_token')
    token_val  = request.form.get('token', '').strip()
    client_id  = request.form.get('client_id', '').strip()

    if token_hint == 'refresh_token':
        token_map = current_app.config.get('REFRESH_TOKEN_MAP', {})
        jti = token_map.pop(token_val, None)
        if jti:
            revoke_token_by_jti(jti)
    else:
        try:
            payload = decode_access_token(token_val, client_id)
            revoke_token_by_jti(payload['jti'])
        except Exception:
            pass  # RFC 7009: always return 200

    log_event('TOKEN_REVOKED', client_id=client_id)
    return jsonify({'status': 'ok'}), 200


# ── Introspection Endpoint (RFC 7662) ──────────────────────────────────────────

@oauth_bp.route('/introspect', methods=['POST'])
def introspect():
    token_val = request.form.get('token', '').strip()
    client_id = request.form.get('client_id', '').strip()
    client_secret = request.form.get('client_secret', '').strip()

    client = OAuthClient.query.filter_by(client_id=client_id).first()
    if not client or client.client_secret != client_secret:
        return _json_error(401, 'invalid_client', 'Client authentication failed')

    try:
        payload = decode_access_token(token_val, client_id)
        return jsonify({'active': True, **payload}), 200
    except Exception:
        return jsonify({'active': False}), 200


# ── UserInfo Endpoint (OIDC Core §5.3) ────────────────────────────────────────

@oauth_bp.route('/userinfo', methods=['GET'])
def userinfo():
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return _json_error(401, 'invalid_token', 'Missing Bearer token')

    token_val = auth[7:].strip()
    # Determine client from token
    try:
        import jwt as pyjwt
        unverified = pyjwt.decode(token_val, options={"verify_signature": False})
        client_id  = unverified.get('aud', '')
        payload    = decode_access_token(token_val, client_id)
        user = db.session.get(User, int(payload['sub']))
        if not user:
            return _json_error(404, 'not_found', 'User not found')
        return jsonify({'sub': payload['sub'], 'email': user.email, 'role': user.role}), 200
    except Exception as e:
        return _json_error(401, 'invalid_token', str(e))


# ── Logout / End Session ───────────────────────────────────────────────────────

@oauth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    sid = session.pop('sso_session_id', None)
    if sid:
        sso = SSOSession.query.filter_by(session_id=sid).first()
        if sso:
            sso.is_active = False
            db.session.commit()
    log_event('SSO_LOGOUT')

    post_logout = request.values.get('post_logout_redirect_uri', '/')
    return redirect(post_logout)
