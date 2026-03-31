"""
Client OAuth Routes
-------------------
/login     → redirect to IDP with PKCE + state
/callback  → receive auth code → exchange → validate ID token → set session
/logout    → revoke token → clear session → redirect to IDP logout
"""
import secrets
from flask import Blueprint, redirect, request, session, url_for, render_template
from client.utils.oidc_client import (
    generate_pkce, build_authorize_url, exchange_code,
    validate_id_token, revoke_token
)
from client.utils.logger import log_event
import os

IDP_BASE = os.getenv('IDP_BASE_URL', 'http://localhost:5008')  # Must match the actual URL where the IDP is hosted

oauth_bp = Blueprint('oauth', __name__)


@oauth_bp.route('/login')
def login():
    """
    Step 1: Generate PKCE + state, store in session, redirect to IDP.
    """
    pkce  = generate_pkce()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)

    # Store in session for callback verification
    session['oauth_state']         = state
    session['oauth_nonce']         = nonce
    session['oauth_code_verifier'] = pkce['code_verifier']

    auth_url = build_authorize_url(
        state          = state,
        code_challenge = pkce['code_challenge'],
        nonce          = nonce,
    )
    return redirect(auth_url)


@oauth_bp.route('/callback')
def callback():
    """
    Step 2: IDP redirects here with code + state.
    Exchange code for tokens, validate ID token, set session.
    """
    error = request.args.get('error')
    if error:
        desc = request.args.get('error_description', 'Unknown error')
        log_event('CALLBACK_ERROR', details=f'{error}: {desc}', severity='warning')
        return render_template('error.html', error=error, description=desc)

    code  = request.args.get('code', '')
    state = request.args.get('state', '')

    # CSRF check — state must match
    if state != session.pop('oauth_state', None):
        log_event('STATE_MISMATCH', severity='critical')
        return render_template('error.html',
                               error='state_mismatch',
                               description='CSRF check failed. Please try logging in again.')

    code_verifier = session.pop('oauth_code_verifier', '')
    nonce         = session.pop('oauth_nonce', '')

    try:
        # Exchange auth code + PKCE verifier for tokens
        tokens = exchange_code(code, code_verifier)
    except Exception as e:
        log_event('TOKEN_EXCHANGE_FAILED', details=str(e), severity='critical')
        return render_template('error.html',
                               error='token_exchange_failed',
                               description=str(e))

    try:
        # Validate ID token signature using IDP's JWKS
        id_claims = validate_id_token(tokens['id_token'], nonce=nonce)
    except Exception as e:
        log_event('ID_TOKEN_INVALID', details=str(e), severity='critical')
        return render_template('error.html',
                               error='invalid_id_token',
                               description=f'ID token validation failed: {e}')

    # All checks passed — set session
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

    # Redirect admin to admin panel, users to chat
    if id_claims.get('role') == 'admin':
        return redirect('/admin')
    return redirect('/chat')


@oauth_bp.route('/logout', methods=['POST', 'GET'])
def logout():
    """Revoke token + clear session + redirect to IDP end-session."""
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

    # Redirect to IDP end-session endpoint
    post_logout = request.host_url.rstrip('/')
    return redirect(f"{IDP_BASE}/oauth/logout?post_logout_redirect_uri={post_logout}/")
