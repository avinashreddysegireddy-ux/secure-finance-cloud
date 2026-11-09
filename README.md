# Secure Finance Cloud (base version)

## Run
    pip install -r requirements.txt
    python app.py          # open http://127.0.0.1:5000

The first registered user becomes **admin** (can open the Audit log).

## Security features
| Feature | Implementation |
|---|---|
| Password storage | Salted PBKDF2 hash (Werkzeug) |
| Data at rest | Amounts & descriptions encrypted with Fernet (AES + HMAC) |
| Brute-force defense | Lock account for 10 min after 5 failed logins |
| CSRF | Per-session token verified on every POST |
| Session safety | HttpOnly, SameSite=Lax cookies, 20 min timeout, session reset on login |
| SQL injection | Parameterised queries only |
| XSS | Jinja2 auto-escaping + Content-Security-Policy |
| IDOR | Every query filtered by the logged-in user's id |
| Accountability | Audit log of logins, failures, and transaction changes |

## Production notes
Keys are auto-generated into `.flask_secret` / `.fernet_key`. In production set
`SFC_SECRET_KEY`, `SFC_FERNET_KEY` env vars (store in a cloud KMS / secrets manager),
serve behind HTTPS (`SFC_HTTPS=1`), and move SQLite -> PostgreSQL/MySQL.
Losing the Fernet key means losing the encrypted data.
