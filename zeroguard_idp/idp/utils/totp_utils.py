import os, pyotp, qrcode, io, base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv

_BASE_DIR  = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
_ENV_PATH  = os.path.join(_BASE_DIR, '.env')
_fernet    = None

def _get_fernet():
    global _fernet
    if _fernet:
        return _fernet
    load_dotenv(_ENV_PATH, override=True)
    key = os.getenv('TOTP_ENCRYPTION_KEY', '').strip().strip('"').strip("'")
    if not key or key == 'your-fernet-key-here':
        key = Fernet.generate_key().decode()
        print(f"[IDP] TOTP_ENCRYPTION_KEY not set — using temp key: {key}")
    _fernet = Fernet(key.encode())
    return _fernet

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def encrypt_secret(secret: str) -> str:
    return _get_fernet().encrypt(secret.encode()).decode()

def decrypt_secret(enc: str) -> str:
    return _get_fernet().decrypt(enc.encode()).decode()

def verify_totp(enc_secret: str, token: str) -> bool:
    try:
        return pyotp.TOTP(decrypt_secret(enc_secret)).verify(token, valid_window=1)
    except Exception:
        return False

def generate_qr(email: str, secret: str) -> str:
    uri = pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name="ZeroGuard IDP")
    qr  = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return base64.b64encode(buf.getvalue()).decode()
