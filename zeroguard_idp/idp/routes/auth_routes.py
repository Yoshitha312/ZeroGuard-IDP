from datetime import datetime, timedelta
import os, bcrypt
from flask import Blueprint, request, jsonify, render_template, redirect
from idp.extensions import db, limiter
from idp.models.models import User
from idp.utils.totp_utils import generate_totp_secret, encrypt_secret, generate_qr
from idp.utils.logger import log_event

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/register', methods=['GET'])
def register_page():
    """Registration UI page — visit /auth/register in browser."""
    return render_template('idp_register.html')


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    # Handle both JSON (API) and form (browser) submissions
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role     = data.get('role', 'user')

    if not email or not password:
        if request.is_json:
            return jsonify({'error': 'Email and password required'}), 400
        return render_template('idp_register.html', error='Email and password required')

    if len(password) < 8:
        if request.is_json:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        return render_template('idp_register.html', error='Password must be at least 8 characters')

    if User.query.filter_by(email=email).first():
        if request.is_json:
            return jsonify({'error': 'Email already registered'}), 409
        return render_template('idp_register.html', error='Email already registered')

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    secret = generate_totp_secret()
    enc    = encrypt_secret(secret)

    user = User(email=email, hashed_password=hashed, role=role,
                totp_secret_encrypted=enc, totp_verified=False)
    db.session.add(user)
    db.session.commit()

    qr_code = generate_qr(email, secret)
    log_event('USER_REGISTERED', user_id=user.id, details=f'role={role}')

    if request.is_json:
        return jsonify({
            'message': 'Registered. Add TOTP secret to Google Authenticator.',
            'user_id': user.id,
            'totp_secret': secret,
            'qr_code': qr_code
        }), 201

    # Browser flow — show QR code page
    return render_template('idp_register_success.html',
                           email=email,
                           totp_secret=secret,
                           qr_code=qr_code)


# FIX: This route must be registered WITHOUT the /auth prefix.
# Blueprint url_prefix='/auth' makes all routes under /auth/...
# so we need a SEPARATE blueprint or register the root route on the app directly.
# Solution: register this route on a different blueprint (no prefix),
# OR handle it in app.py. Here we add it as /auth/ which still works for
# the home page link. We also add a redirect from /auth → /auth/ for cleanliness.
#
# The REAL fix for localhost:5008/ → 404 is in idp/app.py (see app.py fix).
@auth_bp.route('/', endpoint='idp_auth_root')
def idp_auth_root():
    """Redirect /auth/ to the IDP home."""
    return render_template('idp_home.html')
