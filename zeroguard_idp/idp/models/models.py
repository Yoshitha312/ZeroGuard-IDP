from datetime import datetime
from idp.extensions import db


class User(db.Model):
    __tablename__ = 'users'
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(255), unique=True, nullable=False, index=True)
    hashed_password = db.Column(db.String(255), nullable=False)
    role          = db.Column(db.String(50), default='user')
    totp_secret_encrypted = db.Column(db.Text, nullable=True)
    totp_verified = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    lockout_until = db.Column(db.DateTime, nullable=True)
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def to_claims(self):
        return {
            'sub':   str(self.id),
            'email': self.email,
            'role':  self.role,
        }


class OAuthClient(db.Model):
    """Registered OAuth2 client applications."""
    __tablename__ = 'oauth_clients'
    id            = db.Column(db.Integer, primary_key=True)
    client_id     = db.Column(db.String(64), unique=True, nullable=False, index=True)
    client_secret = db.Column(db.String(128), nullable=False)
    client_name   = db.Column(db.String(128), nullable=False)
    redirect_uris = db.Column(db.Text, nullable=False)   # comma-separated
    allowed_scopes = db.Column(db.String(256), default='openid profile email')
    is_active     = db.Column(db.Boolean, default=True)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def has_redirect_uri(self, uri):
        return uri in [u.strip() for u in self.redirect_uris.split(',')]

    def has_scope(self, scope):
        allowed = [s.strip() for s in self.allowed_scopes.split()]
        return all(s in allowed for s in scope.split())


class AuthorizationCode(db.Model):
    """Short-lived single-use authorization codes (RFC 6749 §4.1)."""
    __tablename__ = 'authorization_codes'
    id             = db.Column(db.Integer, primary_key=True)
    code           = db.Column(db.String(128), unique=True, nullable=False, index=True)
    client_id      = db.Column(db.String(64), nullable=False)
    user_id        = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    redirect_uri   = db.Column(db.String(512), nullable=False)
    scope          = db.Column(db.String(256), nullable=False)
    code_challenge         = db.Column(db.String(128), nullable=True)   # PKCE
    code_challenge_method  = db.Column(db.String(10), nullable=True)    # S256
    nonce          = db.Column(db.String(128), nullable=True)           # OIDC
    expires_at     = db.Column(db.DateTime, nullable=False)
    used           = db.Column(db.Boolean, default=False)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='auth_codes')


class TokenRecord(db.Model):
    """Tracks issued / revoked tokens for blacklisting (RFC 7009)."""
    __tablename__ = 'token_records'
    id         = db.Column(db.Integer, primary_key=True)
    jti        = db.Column(db.String(64), unique=True, nullable=False, index=True)
    token_type = db.Column(db.String(20), nullable=False)   # access / refresh / id
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    client_id  = db.Column(db.String(64), nullable=False)
    revoked    = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    issued_at  = db.Column(db.DateTime, default=datetime.utcnow)

    @classmethod
    def is_revoked(cls, jti):
        r = cls.query.filter_by(jti=jti).first()
        return r is not None and r.revoked


class SSOSession(db.Model):
    """Server-side SSO session — one per user login on IDP."""
    __tablename__ = 'sso_sessions'
    id           = db.Column(db.Integer, primary_key=True)
    session_id   = db.Column(db.String(128), unique=True, nullable=False, index=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at   = db.Column(db.DateTime, nullable=False)
    is_active    = db.Column(db.Boolean, default=True)

    user = db.relationship('User', backref='sso_sessions')

    def is_valid(self):
        return self.is_active and self.expires_at > datetime.utcnow()


class AuditLog(db.Model):
    __tablename__ = 'idp_audit_logs'
    id         = db.Column(db.Integer, primary_key=True)
    event      = db.Column(db.String(100), nullable=False)
    user_id    = db.Column(db.Integer, nullable=True)
    client_id  = db.Column(db.String(64), nullable=True)
    details    = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    severity   = db.Column(db.String(20), default='info')
    timestamp  = db.Column(db.DateTime, default=datetime.utcnow, index=True)
