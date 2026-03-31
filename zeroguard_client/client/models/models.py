"""
Client DB Models
----------------
Client stores NO auth data — identity lives entirely in the IDP.
Only chat history and local session cache are stored here.
"""
from datetime import datetime
from client.extensions import db


class ChatHistory(db.Model):
    __tablename__ = 'chat_history'
    id          = db.Column(db.Integer, primary_key=True)
    user_sub    = db.Column(db.String(64), nullable=False, index=True)  # IDP user sub
    user_email  = db.Column(db.String(255), nullable=False)
    user_role   = db.Column(db.String(50),  default='user')
    prompt      = db.Column(db.Text, nullable=False)
    response    = db.Column(db.Text, nullable=False)
    threat_level= db.Column(db.String(20),  default='normal')
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id':           self.id,
            'prompt':       self.prompt,
            'response':     self.response,
            'threat_level': self.threat_level,
            'user_email':   self.user_email,
            'created_at':   self.created_at.isoformat(),
        }


class AuditLog(db.Model):
    __tablename__ = 'client_audit_logs'
    id         = db.Column(db.Integer, primary_key=True)
    log_type   = db.Column(db.String(50),  nullable=False)
    user_sub   = db.Column(db.String(64),  nullable=True)
    action     = db.Column(db.String(255), nullable=False)
    details    = db.Column(db.Text,        nullable=True)
    ip_address = db.Column(db.String(45),  nullable=True)
    severity   = db.Column(db.String(20),  default='info')
    timestamp  = db.Column(db.DateTime,    default=datetime.utcnow)
