"""
Client Auth Middleware
----------------------
Validates RS256 tokens using IDP's public JWKS — no shared secret.

FIX: admin_required was incorrectly stacking @api_auth_required as an inner
     decorator using @wraps+@api_auth_required together, which caused the
     wrapper to be called twice (double auth check + double wrapping).
     Fixed by calling validate_access_token directly inside admin_required.
"""
from functools import wraps
from flask import session, redirect, jsonify, request
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
            request.user_claims = payload
        except Exception:
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
    """
    Require admin role.
    FIX: Do NOT nest @api_auth_required here — call validate_access_token
    directly to avoid double-wrapping which breaks Flask's routing.
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        access_token = session.get('access_token')
        if not access_token:
            return jsonify({'error': 'Not authenticated', 'code': 'NO_SESSION'}), 401
        try:
            payload = validate_access_token(access_token)
            request.user_claims = payload
        except Exception:
            session.clear()
            return jsonify({'error': 'Invalid or expired token', 'code': 'TOKEN_INVALID'}), 401

        if payload.get('role') != 'admin':
            return jsonify({'error': 'Admin role required'}), 403
        return fn(*args, **kwargs)
    return wrapper
