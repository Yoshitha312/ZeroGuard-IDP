import os, re
from dotenv import load_dotenv

_BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
load_dotenv(os.path.join(_BASE_DIR, '.env'), override=True)

MALICIOUS_PATTERNS = [
    r"(DROP\s+TABLE|DELETE\s+FROM\s+\w|UNION\s+SELECT|OR\s+1\s*=\s*1)",
    r"(<script[\s>]|javascript:\s*alert|onerror\s*=|onload\s*=)",
    r"(ignore\s+(all\s+)?previous\s+instructions|forget\s+your\s+(previous\s+)?instructions|jailbreak)",
    r"(\.\./\.\./|/etc/passwd|/etc/shadow)",
]
SUSPICIOUS_PATTERNS = [
    r"(how\s+do\s+i\s+hack\b|step\s+by\s+step\s+exploit)",
    r"(how\s+to\s+bypass\s+authentication|disable\s+all\s+security)",
    r"(steal\s+(user\s+)?data|exfiltrat|dump\s+the\s+database)",
]


def analyze_threat(prompt: str) -> dict:
    p = prompt.lower()
    for pat in MALICIOUS_PATTERNS:
        if re.search(pat, p, re.IGNORECASE):
            return {'level': 'malicious', 'reason': 'Attack pattern', 'should_block': True}
    for pat in SUSPICIOUS_PATTERNS:
        if re.search(pat, p, re.IGNORECASE):
            return {'level': 'suspicious', 'reason': 'Suspicious pattern', 'should_block': False}
    return {'level': 'normal', 'reason': 'Clean', 'should_block': False}


def get_ai_response(prompt: str, role: str, email: str) -> str:
    load_dotenv(os.path.join(_BASE_DIR, '.env'), override=True)
    groq_key = os.getenv('GROQ_API_KEY', '').strip().strip('"').strip("'")

    if groq_key and groq_key != 'your-groq-api-key-here':
        try:
            import requests as req
            resp = req.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"},
                json={
                    "model": "llama-3.1-8b-instant",
                    "messages": [
                        {"role": "system", "content": _system_prompt(role)},
                        {"role": "user",   "content": prompt}
                    ],
                    "max_tokens": 1024, "temperature": 0.7
                },
                timeout=30
            )
            if resp.status_code == 200:
                return resp.json()["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"[AI] Groq error: {e}")

    return _fallback(prompt, role)


def _system_prompt(role: str) -> str:
    base = ("You are a helpful AI assistant in a secure IAM platform. "
            "Answer ANY question — general knowledge, coding, science, geography, history. "
            "For IAM/security topics also explain how this system handles it.")
    if role == 'admin':
        return base + " ADMIN MODE: Give full technical detail for security topics."
    return base + " USER MODE: Keep explanations friendly and accessible."


def _fallback(prompt: str, role: str) -> str:
    p = prompt.lower()
    px = "🔒 **[Admin]**\n\n" if role == 'admin' else ""
    if 'jwt'       in p: return px + "**JWT** is a compact token for stateless auth. Structure: `header.payload.signature` (RS256 signed by IDP's private key). This system uses JWTs issued by ZeroGuard IDP — clients verify them using the IDP's public JWKS."
    if 'totp'      in p or 'mfa' in p: return px + "**TOTP** is the second factor. The IDP handles TOTP — the client app never sees your credentials or TOTP codes. Only the IDP validates them and issues tokens."
    if 'oauth'     in p: return px + "**OAuth 2.0** is the authorization framework. This system uses Authorization Code + PKCE flow: client → IDP → user login → auth code → token exchange → access token."
    if 'oidc'      in p or 'openid' in p: return px + "**OIDC** extends OAuth 2.0 with identity. The IDP issues an ID Token (RS256 JWT) with claims: sub, email, role, nonce. The client verifies it using IDP's JWKS."
    if 'pkce'      in p: return px + "**PKCE** (RFC 7636) prevents auth code interception. Client generates code_verifier → hashes to code_challenge → sent to IDP. On token exchange, client sends verifier — IDP verifies the hash matches."
    if 'sso'       in p: return px + "**SSO** means login once, access multiple apps. The IDP sets a session cookie. If you visit another client app, the IDP recognises your session and issues a code without re-prompting for credentials."
    if 'zero trust' in p: return px + "**Zero Trust** in this system: the client never trusts its own session — it validates every access token against the IDP's JWKS on every request. No shared secrets between client and IDP."
    return (f"You asked: *\"{prompt}\"*\n\nAdd your **Groq API key** to `.env` as `GROQ_API_KEY=gsk_...` and restart for full AI answers.\n\nGet a free key at https://console.groq.com")


def explain_iam_decision(action: str, granted: bool, role: str, resource: str) -> str:
    s = "GRANTED" if granted else "DENIED"
    if granted:
        return f"✅ Access {s}: role='{role}' → '{action}'. Token verified via IDP JWKS. Permissions confirmed."
    return f"🚫 Access {s}: role='{role}' → '{action}'. Insufficient permissions per IDP token claims."
