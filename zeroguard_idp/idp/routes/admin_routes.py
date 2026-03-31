import secrets
from flask import Blueprint, request, jsonify, render_template, session
from idp.extensions import db
from idp.models.models import OAuthClient, User, AuditLog, TokenRecord
from idp.utils.logger import log_event

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def _require_admin():
    """Simple session-based admin check for IDP admin panel."""
    return session.get('idp_admin') is True


@admin_bp.route('/')
def dashboard():
    if not _require_admin():
        return render_template('idp_admin_login.html')
    users   = User.query.count()
    clients = OAuthClient.query.count()
    logs    = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(20).all()
    return render_template('idp_admin.html', users=users, clients=clients, logs=logs)


@admin_bp.route('/login', methods=['POST'])
def admin_login():
    import bcrypt, os
    email    = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '').strip()
    user = User.query.filter_by(email=email, role='admin').first()
    if user and bcrypt.checkpw(password.encode(), user.hashed_password.encode()):
        session['idp_admin'] = True
        session['idp_admin_email'] = email
        return jsonify({'redirect': '/admin/'}), 200
    return jsonify({'error': 'Invalid admin credentials'}), 401


@admin_bp.route('/logout', methods=['POST'])
def admin_logout():
    session.pop('idp_admin', None)
    return jsonify({'redirect': '/admin/'}), 200


# ── Client Management ──────────────────────────────────────────────

@admin_bp.route('/clients', methods=['GET'])
def list_clients():
    if not _require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    clients = OAuthClient.query.all()
    return jsonify([{
        'id': c.id, 'client_id': c.client_id, 'client_name': c.client_name,
        'redirect_uris': c.redirect_uris, 'allowed_scopes': c.allowed_scopes,
        'is_active': c.is_active, 'created_at': c.created_at.isoformat()
    } for c in clients])


@admin_bp.route('/clients', methods=['POST'])
def create_client():
    if not _require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    client_id     = secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    client = OAuthClient(
        client_id      = client_id,
        client_secret  = client_secret,
        client_name    = data.get('client_name', 'New Client'),
        redirect_uris  = data.get('redirect_uris', 'http://localhost:5001/callback'),
        allowed_scopes = data.get('allowed_scopes', 'openid profile email')
    )
    db.session.add(client)
    db.session.commit()
    log_event('CLIENT_CREATED', details=f'client_name={client.client_name}')
    return jsonify({'client_id': client_id, 'client_secret': client_secret}), 201


@admin_bp.route('/clients/<int:cid>', methods=['DELETE'])
def delete_client(cid):
    if not _require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    c = OAuthClient.query.get_or_404(cid)
    db.session.delete(c)
    db.session.commit()
    return jsonify({'message': 'Client deleted'}), 200


# ── User Management ────────────────────────────────────────────────

@admin_bp.route('/users', methods=['GET'])
def list_users():
    if not _require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    users = User.query.all()
    return jsonify([{
        'id': u.id, 'email': u.email, 'role': u.role,
        'totp_verified': u.totp_verified, 'is_active': u.is_active,
        'failed_attempts': u.failed_attempts,
        'created_at': u.created_at.isoformat()
    } for u in users])


@admin_bp.route('/users/<int:uid>/unlock', methods=['POST'])
def unlock_user(uid):
    if not _require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    u = User.query.get_or_404(uid)
    u.failed_attempts = 0
    u.lockout_until   = None
    db.session.commit()
    return jsonify({'message': 'User unlocked'}), 200


@admin_bp.route('/logs', methods=['GET'])
def get_logs():
    if not _require_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify([{
        'id': l.id, 'event': l.event, 'user_id': l.user_id,
        'client_id': l.client_id, 'details': l.details,
        'ip_address': l.ip_address, 'severity': l.severity,
        'timestamp': l.timestamp.isoformat()
    } for l in logs])
