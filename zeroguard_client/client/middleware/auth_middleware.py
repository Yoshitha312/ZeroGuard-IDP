"""
Client Auth Middleware
----------------------
Replaces the old PEP/PDP middleware.
Now validates RS256 tokens using IDP's public JWKS — no shared secret.
"""
from functools import wraps
from flask import session, redirect, url_for, jsonify, request
from client.utils.oidc_client import validate_access_token


def login_required(fn):
    """Require a valid OIDC session — redirect to /login if not present."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        access_token = session.get('access_token')
        if not access_token:
            return redirect('/login')
        try:
            payload = validate_access_token(access_token)
            # Attach claims to request context
            request.user_claims = payload
        except Exception as e:
            # Token expired or invalid — redirect to re-login
            session.clear()
            return redirect('/login')
        return fn(*args, **kwargs)
    return wrapper


def api_auth_required(fn):
    """For API endpoints — return 401 JSON instead of redirect."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        access_token = session.get('access_token')
        if not access_token:
            return jsonify({'error': 'Not authenticated', 'code': 'NO_SESSION'}), 401
        try:
            payload = validate_access_token(access_token)
            request.user_claims = payload
        except Exception as e:
            err = str(e)
            if 'expired' in err.lower():
                # Try to refresh automatically
                refresh_token = session.get('refresh_token')
                if refresh_token:
                    try:
                        from client.utils.oidc_client import refresh_access_token
                        tokens = refresh_access_token(refresh_token)
                        session['access_token']  = tokens['access_token']
                        session['refresh_token'] = tokens.get('refresh_token', refresh_token)
                        payload = validate_access_token(tokens['access_token'])
                        request.user_claims = payload
                        return fn(*args, **kwargs)
                    except Exception:
                        pass
                session.clear()
                return jsonify({'error': 'Token expired', 'code': 'TOKEN_EXPIRED'}), 401
            session.clear()
            return jsonify({'error': 'Invalid token', 'code': 'TOKEN_INVALID'}), 401
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    """Require admin role."""
    @wraps(fn)
    @api_auth_required
    def wrapper(*args, **kwargs):
        claims = getattr(request, 'user_claims', {})
        if claims.get('role') != 'admin':
            return jsonify({'error': 'Admin role required'}), 403
        return fn(*args, **kwargs)
    return wrapper
