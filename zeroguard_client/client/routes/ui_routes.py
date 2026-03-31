from flask import Blueprint, render_template, session, redirect, request, jsonify
from client.middleware.auth_middleware import login_required, admin_required
from client.models.models import ChatHistory, AuditLog
from client.extensions import db

ui_bp = Blueprint('ui', __name__)


@ui_bp.route('/')
def index():
    user = session.get('user')
    return render_template('index.html', user=user)


@ui_bp.route('/chat')
@login_required
def chat():
    return render_template('chat.html', user=session.get('user'))


@ui_bp.route('/admin')
@login_required
def admin():
    user = session.get('user', {})
    if user.get('role') != 'admin':
        return redirect('/chat')
    return render_template('admin.html', user=user)


@ui_bp.route('/api/admin/stats')
@admin_required
def admin_stats():
    total  = ChatHistory.query.count()
    mal    = ChatHistory.query.filter_by(threat_level='malicious').count()
    sus    = ChatHistory.query.filter_by(threat_level='suspicious').count()
    logs   = AuditLog.query.count()
    return jsonify({'chats': {'total': total, 'malicious': mal, 'suspicious': sus},
                    'logs': {'total': logs}}), 200


@ui_bp.route('/api/admin/logs')
@admin_required
def admin_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify([{
        'id': l.id, 'log_type': l.log_type, 'user_sub': l.user_sub,
        'action': l.action, 'details': l.details,
        'severity': l.severity, 'timestamp': l.timestamp.isoformat()
    } for l in logs]), 200


@ui_bp.route('/api/me')
def me():
    user = session.get('user')
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify(user), 200
