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

    # FIX: use_reloader=False prevents Flask from spawning a second worker
    # process. With use_reloader=True (the default when debug=True), Flask
    # starts TWO processes:
    #   1. The main process — loads app, generates RSA keys, seeds DB
    #   2. The reloader process — loads app AGAIN, sees keys on disk but
    #      the key_manager._private_key global is None in this new process,
    #      so _ensure_keys() runs again and generates a NEW key pair,
    #      overwriting the keys on disk mid-request.
    # Result: token signed with key-A, client fetches JWKS and gets key-B
    #         → "Signature has expired" (misleading error for key mismatch)
    # Fix: disable the reloader. You still get debug error pages and
    #      auto-reload on code changes is just done manually (Ctrl+C → restart).
    app.run(
        debug=debug,
        port=port,
        host='0.0.0.0',
        use_reloader=False,   # ← THE FIX
    )