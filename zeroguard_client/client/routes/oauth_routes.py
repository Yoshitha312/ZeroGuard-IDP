"""
Client OAuth Routes
-------------------
FIX for session_lost on Chrome (cross-port redirect drops session cookie):

Chrome with SameSite=Lax blocks cookies when the TOP-LEVEL redirect
arrives from a different origin. localhost:5008 → localhost:5001 is
treated as cross-site in Chrome because ports differ.

Solution: store oauth_state / code_verifier / nonce in a server-side
Python dict (_STATE_STORE) keyed by the state token. The IDP echoes
the state token back in the callback URL query param, so we can look
up the verifier without ANY cookie from the /login→IDP→/callback trip.

The session cookie is only set IN the /callback response (same-origin:
localhost:5001 → browser), so Chrome sends it correctly on all
subsequent /api/chat/... requests.
"""
import secrets
import time
import os
from flask import Blueprint, redirect, request, session, render_template
from client.utils.oidc_client import (
    generate_pkce, build_authorize_url, exchange_code,
    validate_id_token, revoke_token
)
from client.utils.logger import log_event

IDP_BASE = os.getenv('IDP_BASE_URL', 'http://localhost:5008')

oauth_bp = Blueprint('oauth', __name__)

# ── Server-side OAuth state store ─────────────────────────────────────────────
# Keyed by state token. Values: {code_verifier, nonce, expires}.
# No cookie required — state token is echoed back by IDP in the callback URL.
_STATE_STORE: dict = {}
_STATE_TTL = 600  # 10 minutes


def _store_pkce(state: str, code_verifier: str, nonce: str):
    _STATE_STORE[state] = {
        'code_verifier': code_verifier,
        'nonce':         nonce,
        'expires':       time.time() + _STATE_TTL,
    }
    # Prune expired entries
    expired = [k for k, v in list(_STATE_STORE.items()) if v['expires'] < time.time()]
    for k in expired:
        _STATE_STORE.pop(k, None)


def _retrieve_pkce(state: str) -> dict | None:
    entry = _STATE_STORE.pop(state, None)
    if not entry:
        return None
    if entry['expires'] < time.time():
        return None   # expired
    return entry


# ── Routes ─────────────────────────────────────────────────────────────────────

@oauth_bp.route('/login')
def login():
    pkce  = generate_pkce()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)

    # Store server-side — no cookie needed for this data
    _store_pkce(state, pkce['code_verifier'], nonce)

    auth_url = build_authorize_url(
        state          = state,
        code_challenge = pkce['code_challenge'],
        nonce          = nonce,
    )
    return redirect(auth_url)


@oauth_bp.route('/callback')
def callback():
    error = request.args.get('error')
    if error:
        desc = request.args.get('error_description', 'Unknown error')
        log_event('CALLBACK_ERROR', details=f'{error}: {desc}', severity='warning')
        return render_template('error.html', error=error, description=desc)

    code  = request.args.get('code', '').strip()
    state = request.args.get('state', '').strip()

    if not code or not state:
        return render_template('error.html',
                               error='missing_params',
                               description='Missing code or state parameter in callback.')

    # Look up PKCE params from server-side store using state token
    pkce_data = _retrieve_pkce(state)

    if not pkce_data:
        log_event('STATE_MISMATCH', severity='critical',
                  details=f'state={state[:8]}... not found in store (expired or reused)')
        return render_template('error.html',
                               error='state_mismatch',
                               description=(
                                   'Login session expired or state was already used. '
                                   'Please try logging in again.'
                               ))

    code_verifier = pkce_data['code_verifier']
    nonce         = pkce_data['nonce']

    # Exchange auth code + PKCE verifier for tokens
    try:
        tokens = exchange_code(code, code_verifier)
    except Exception as e:
        log_event('TOKEN_EXCHANGE_FAILED', details=str(e), severity='critical')
        return render_template('error.html',
                               error='token_exchange_failed',
                               description=str(e))

    # Validate ID token signature using IDP's JWKS
    try:
        id_claims = validate_id_token(tokens['id_token'], nonce=nonce)
    except Exception as e:
        log_event('ID_TOKEN_INVALID', details=str(e), severity='critical')
        return render_template('error.html',
                               error='invalid_id_token',
                               description=f'ID token validation failed: {e}')

    # All good — write session (this cookie is set by localhost:5001 response,
    # so Chrome will accept and send it on all future localhost:5001 requests)
    session.clear()
    session['access_token']  = tokens['access_token']
    session['refresh_token'] = tokens.get('refresh_token', '')
    session['id_token']      = tokens['id_token']
    session['user'] = {
        'sub':   id_claims['sub'],
        'email': id_claims.get('email', ''),
        'role':  id_claims.get('role', 'user'),
    }

    log_event('LOGIN_SUCCESS', user_sub=id_claims['sub'],
              details=f"email={id_claims.get('email')} role={id_claims.get('role')}")

    if id_claims.get('role') == 'admin':
        return redirect('/admin')
    return redirect('/chat')


@oauth_bp.route('/logout', methods=['POST', 'GET'])
def logout():
    access_token  = session.get('access_token', '')
    refresh_token = session.get('refresh_token', '')
    user          = session.get('user', {})

    if access_token:
        try:
            revoke_token(access_token, 'access_token')
        except Exception:
            pass
    if refresh_token:
        try:
            revoke_token(refresh_token, 'refresh_token')
        except Exception:
            pass

    log_event('LOGOUT', user_sub=user.get('sub'))
    session.clear()

    post_logout = request.host_url.rstrip('/')
    return redirect(f"{IDP_BASE}/oauth/logout?post_logout_redirect_uri={post_logout}/")
