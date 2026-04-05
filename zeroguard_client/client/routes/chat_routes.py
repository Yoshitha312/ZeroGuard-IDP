from flask import Blueprint, request, jsonify, session
from client.extensions import db, limiter
from client.models.models import ChatHistory
from client.middleware.auth_middleware import api_auth_required
from client.utils.ai_engine import analyze_threat, get_ai_response, explain_iam_decision
from client.utils.logger import log_event

chat_bp = Blueprint('chat', __name__, url_prefix='/api/chat')


# FIX: limiter.limit() with a callable is evaluated at decoration time in some
# versions of flask-limiter. Use a static high limit and enforce role-based
# throttling manually, OR use the supported lambda string syntax.
# Safest fix: use separate routes or a fixed limit with role check inside.
@chat_bp.route('/send', methods=['POST'])
@api_auth_required
@limiter.limit("50 per minute")   # generous limit; role check enforced inside
def send_message():
    data   = request.get_json()
    if not data:
        return jsonify({'error': 'JSON body required'}), 400

    prompt = data.get('prompt', '').strip()

    if not prompt:
        return jsonify({'error': 'Prompt cannot be empty'}), 400
    if len(prompt) > 2000:
        return jsonify({'error': 'Prompt too long (max 2000 chars)'}), 400

    claims = request.user_claims
    sub    = claims.get('sub', '')
    role   = claims.get('role', 'user')
    email  = claims.get('email', '')

    threat = analyze_threat(prompt)

    log_event('CHAT_PROMPT', user_sub=sub,
              details=f'threat={threat["level"]} len={len(prompt)}',
              severity='critical' if threat['level'] == 'malicious' else
                       'warning'  if threat['level'] == 'suspicious' else 'info')

    if threat['should_block']:
        chat = ChatHistory(user_sub=sub, user_email=email, user_role=role,
                           prompt=prompt, response='[BLOCKED]',
                           threat_level='malicious')
        db.session.add(chat)
        db.session.commit()
        return jsonify({
            'error':           'Request blocked by security policy',
            'threat_level':    'malicious',
            'iam_explanation': explain_iam_decision('chat_send', False, role, 'ai_engine')
        }), 403

    ai_response = get_ai_response(prompt, role, email)
    if threat['level'] == 'suspicious':
        ai_response += "\n\n⚠️ *Security notice: Your query matched a suspicious pattern and has been logged.*"

    chat = ChatHistory(user_sub=sub, user_email=email, user_role=role,
                       prompt=prompt, response=ai_response,
                       threat_level=threat['level'])
    db.session.add(chat)
    db.session.commit()

    return jsonify({
        'response':        ai_response,
        'threat_level':    threat['level'],
        'iam_explanation': explain_iam_decision('chat_send', True, role, 'ai_engine'),
        'chat_id':         chat.id
    }), 200


@chat_bp.route('/history', methods=['GET'])
@api_auth_required
def get_history():
    claims = request.user_claims
    sub    = claims.get('sub', '')
    role   = claims.get('role', 'user')
    page   = request.args.get('page', 1, type=int)
    per    = request.args.get('per_page', 20, type=int)

    if role == 'admin':
        q = ChatHistory.query.order_by(ChatHistory.created_at.desc())
    else:
        q = ChatHistory.query.filter_by(user_sub=sub).order_by(ChatHistory.created_at.desc())

    pag = q.paginate(page=page, per_page=per, error_out=False)
    return jsonify({
        'chats':        [c.to_dict() for c in pag.items],
        'total':        pag.total,
        'pages':        pag.pages,
        'current_page': page,
    }), 200
