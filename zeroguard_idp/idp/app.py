import os
from flask import Flask, render_template
from flask_cors import CORS
from dotenv import load_dotenv
from idp.extensions import db, limiter

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(os.path.join(_BASE_DIR, '.env'), override=True)


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(_BASE_DIR, 'idp', 'templates'),
        static_folder=os.path.join(_BASE_DIR, 'idp', 'static')
    )
    app.config['SECRET_KEY']                  = os.getenv('SECRET_KEY', 'idp-dev-secret')
    app.config['SQLALCHEMY_DATABASE_URI']     = f"sqlite:///{os.path.join(_BASE_DIR, 'idp.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['RATELIMIT_STORAGE_URL']       = 'memory://'
    app.config['REFRESH_TOKEN_MAP']           = {}

    db.init_app(app)
    limiter.init_app(app)
    CORS(app, resources={r"/oauth/*": {"origins": "*"}, r"/.well-known/*": {"origins": "*"}})

    from idp.routes.oauth_routes     import oauth_bp
    from idp.routes.discovery_routes import discovery_bp
    from idp.routes.admin_routes     import admin_bp
    from idp.routes.auth_routes      import auth_bp

    app.register_blueprint(oauth_bp)
    app.register_blueprint(discovery_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(auth_bp)

    # FIX: Register root route directly on the app so localhost:5008/ works.
    # The auth_bp has url_prefix='/auth', so its routes are /auth/...
    # Without this, visiting localhost:5008/ gives 404.
    @app.route('/')
    def idp_home():
        return render_template('idp_home.html')

    with app.app_context():
        db.create_all()
        _seed_data()

    return app


def _seed_data():
    """Create default admin user + register ZeroGuard client."""
    import bcrypt, secrets
    from idp.models.models import User, OAuthClient
    from idp.utils.totp_utils import generate_totp_secret, encrypt_secret

    if not User.query.filter_by(role='admin').first():
        secret = generate_totp_secret()
        hashed = bcrypt.hashpw(b'Admin@1234', bcrypt.gensalt()).decode()
        admin  = User(email='admin@zeroguard.local', hashed_password=hashed,
                      role='admin', totp_secret_encrypted=encrypt_secret(secret))
        db.session.add(admin)
        db.session.commit()
        print("\n" + "="*55)
        print("  IDP ADMIN CREATED")
        print("  Email:    admin@zeroguard.local")
        print("  Password: Admin@1234")
        print(f"  TOTP Secret: {secret}")
        print("="*55)

    if not OAuthClient.query.filter_by(client_id='zeroguard-client').first():
        client_secret = secrets.token_urlsafe(32)
        c = OAuthClient(
            client_id      = 'zeroguard-client',
            client_secret  = client_secret,
            client_name    = 'ZeroGuard Chat App',
            redirect_uris  = 'http://localhost:5001/callback',
            allowed_scopes = 'openid profile email roles'
        )
        db.session.add(c)
        db.session.commit()
        print("\n" + "="*55)
        print("  OAUTH CLIENT REGISTERED")
        print("  client_id:     zeroguard-client")
        print(f"  client_secret: {client_secret}")
        print("  Copy client_secret to client/.env as CLIENT_SECRET")
        print("="*55 + "\n")
