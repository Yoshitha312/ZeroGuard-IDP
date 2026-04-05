import os
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
from client.extensions import db, limiter

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv(os.path.join(_BASE_DIR, '.env'), override=True)


def create_app():
    app = Flask(
        __name__,
        template_folder=os.path.join(_BASE_DIR, 'client', 'templates'),
        static_folder=os.path.join(_BASE_DIR, 'client', 'static')
    )

    secret = os.getenv('SECRET_KEY', 'client-dev-secret-fallback-change-this')
    app.config['SECRET_KEY']                     = secret
    app.config['SQLALCHEMY_DATABASE_URI']        = f"sqlite:///{os.path.join(_BASE_DIR, 'client.db')}"
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['RATELIMIT_STORAGE_URL']          = 'memory://'

    # Chrome on HTTP localhost:
    # SameSite=Lax blocks cookies when redirect arrives FROM a different
    # origin (localhost:5008 → localhost:5001). We solve this by NOT
    # relying on session cookies to carry oauth_state across the IDP
    # redirect — instead oauth_routes.py uses a server-side _STATE_STORE
    # dict. The session cookie is only needed AFTER /callback sets it,
    # which is a same-origin response (localhost:5001 → localhost:5001).
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['SESSION_COOKIE_SECURE']   = False  # HTTP localhost
    app.config['SESSION_COOKIE_NAME']     = 'zeroguard_session'

    db.init_app(app)
    limiter.init_app(app)
    CORS(app, supports_credentials=True)

    from client.routes.oauth_routes import oauth_bp
    from client.routes.chat_routes  import chat_bp
    from client.routes.ui_routes    import ui_bp

    app.register_blueprint(oauth_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(ui_bp)

    with app.app_context():
        db.create_all()

    return app
