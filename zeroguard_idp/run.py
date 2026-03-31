import os
from idp.app import create_app

app = create_app()

if __name__ == '__main__':
    port  = int(os.getenv('PORT', 5008))
    debug = os.getenv('FLASK_DEBUG', '1') == '1'

    print("\n" + "="*55)
    print("  ZeroGuard IDP — Identity Provider")
    print("="*55)
    print(f"  → http://localhost:{port}")
    print(f"  → Discovery: http://localhost:{port}/.well-known/openid-configuration")
    print(f"  → JWKS:      http://localhost:{port}/.well-known/jwks.json")
    print(f"  → Admin:     http://localhost:{port}/admin/")
    print("="*55 + "\n")

    app.run(debug=debug, port=port, host='0.0.0.0')
