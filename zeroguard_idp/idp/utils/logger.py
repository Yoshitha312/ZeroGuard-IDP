import logging, os
from datetime import datetime
from flask import request

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_LOG_DIR  = os.path.join(_BASE_DIR, 'logs')
os.makedirs(_LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(_LOG_DIR, 'idp.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ZeroGuardIDP')

def log_event(event: str, user_id=None, client_id=None, details=None, severity='info'):
    from idp.extensions import db
    from idp.models.models import AuditLog
    ip = request.remote_addr if request else 'system'
    msg = f"[{event}] user={user_id} client={client_id} | {details} | ip={ip}"
    getattr(logger, 'critical' if severity == 'critical' else 'warning' if severity == 'warning' else 'info')(msg)
    try:
        db.session.add(AuditLog(event=event, user_id=user_id, client_id=client_id, details=details, ip_address=ip, severity=severity))
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")
