import logging, os
from datetime import datetime
from flask import request as flask_request

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_LOG_DIR  = os.path.join(_BASE_DIR, 'logs')
os.makedirs(_LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(_LOG_DIR, 'client.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ZeroGuardClient')


def log_event(action: str, user_sub=None, details=None, severity='info'):
    from client.extensions import db
    from client.models.models import AuditLog
    try:
        ip = flask_request.remote_addr
    except Exception:
        ip = 'system'
    msg = f"[{action}] sub={user_sub} | {details} | ip={ip}"
    getattr(logger, 'critical' if severity == 'critical' else
                    'warning'  if severity == 'warning'  else 'info')(msg)
    try:
        db.session.add(AuditLog(log_type='client', user_sub=user_sub,
                                action=action, details=details,
                                ip_address=ip, severity=severity))
        db.session.commit()
    except Exception as e:
        logger.error(f"DB log failed: {e}")
