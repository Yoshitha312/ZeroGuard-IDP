import os
from client.app import create_app

app = create_app()

if __name__ == '__main__':
    port  = int(os.getenv('PORT', 5001))
    debug = os.getenv('FLASK_DEBUG', '1') == '1'

    print("\n" + "="*55)
    print("  ZeroGuard Client App")
    print("="*55)
    print(f"  → http://localhost:{port}")
    print(f"  → IDP: {os.getenv('IDP_BASE_URL','http://localhost:5008')}")
    print("  Make sure IDP is running first!")
    print("="*55 + "\n")

    app.run(debug=debug, port=port, host='0.0.0.0')
