from datetime import datetime, timedelta
import os, bcrypt
from flask import Blueprint, request, jsonify
from idp.extensions import db, limiter
from idp.models.models import User
from idp.utils.totp_utils import generate_totp_secret, encrypt_secret, generate_qr
from idp.utils.logger import log_event

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')


@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data     = request.get_json()
    email    = data.get('email', '').strip().lower()
    password = data.get('password', '')
    role     = data.get('role', 'user')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already registered'}), 409

    hashed  = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    secret  = generate_totp_secret()
    enc     = encrypt_secret(secret)

    user = User(email=email, hashed_password=hashed, role=role,
                totp_secret_encrypted=enc, totp_verified=False)
    db.session.add(user)
    db.session.commit()

    qr_code = generate_qr(email, secret)
    log_event('USER_REGISTERED', user_id=user.id, details=f'role={role}')

    return jsonify({
        'message': 'User registered. Add TOTP secret to Google Authenticator.',
        'user_id': user.id,
        'totp_secret': secret,
        'qr_code': qr_code
    }), 201
