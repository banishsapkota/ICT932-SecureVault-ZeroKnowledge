# SecureVault MVP operations and security boundaries

## First run

Use Python 3.14. Follow the README environment setup, generate a random Flask secret, then run `python scripts/init_db.py` and `python src/app.py`. The development server binds to loopback. Visit `/auth/register`, choose a username and login password, scan the local QR code with an authenticator, and confirm a TOTP code. No vault or admin access is granted before verification. Each login requires a fresh TOTP code; a code already consumed during setup cannot be reused.

On the dashboard choose a **separate** master passphrase (12 or more characters). The first unlock creates an encrypted key verification record. Later unlocks verify it before allowing writes. There is no master passphrase recovery, password reset, TOTP recovery, or passphrase rotation in this MVP. Back up the SQLite database and keep an independent secure copy of your authenticator recovery material.

Grant an existing account the admin role from a trusted local terminal:

```sh
python -m flask --app src.app make-admin YOUR_USERNAME
```

Admins can review the latest 100 audit events and temporarily lock accounts. Their session cannot retrieve another user's vault. Account locking blocks existing sessions on subsequent requests. It cannot erase plaintext already viewed in another browser.

## Existing data and preserved content

The original repository contained misplaced code (including HTML in `src/__init__.py`, authentication routes in admin/audit files, and Python in the stylesheet). The MVP repairs those files, retains the useful admin template in its intended location, and preserves project licensing, security policy, team details, and academic evidence placeholders. Older unused template files remain for reference; only the new routes/templates are active.

Initialization creates missing tables only and never drops or rewrites existing data. An older database is **not automatically migrated**. Back it up and use a new `DATABASE_URL` for this MVP. Old server-encrypted records cannot become browser-encrypted records without an explicit trusted export/re-encryption migration. Do not delete an existing database to resolve schema errors.

## Cryptographic design

Web Crypto derives a non-exportable AES-256-GCM key using PBKDF2-HMAC-SHA-256 with 600,000 iterations and a random per-account salt. Each encryption uses a fresh random 96-bit nonce and a 128-bit authentication tag. The browser encrypts labels, usernames, and passwords together. The API accepts only bounded base64 ciphertext/nonce envelopes, and lists/deletes only the authenticated owner's records. A uniqueness constraint rejects reuse of stored entry nonces. The browser refuses the wrong master passphrase and detects modified ciphertext. Locking clears fields and rendered secrets, drops the key reference, and invalidates pending asynchronous rendering. The vault locks after five minutes of inactivity and on page exit/logout. JavaScript garbage collection cannot guarantee physical memory erasure.

This is a zero-knowledge-style storage demonstration, not a formal zero-knowledge proof. The server still knows account identities, TOTP seeds, IP addresses, timestamps, ciphertext sizes and record counts. Login passwords reach Flask over HTTPS; use a distinct master passphrase to preserve the vault separation. A stolen database permits offline master-passphrase guessing. A compromised server can serve malicious JavaScript, and XSS, browser extensions, endpoint compromise, deletion, or ciphertext rollback are outside the protection offered by AES-GCM. There is no external rollback protection or independently trusted client.

## Authentication, deployment and monitoring

Argon2id hashes login passwords. Password verification alone creates only a five-minute pending session. TOTP enrollment requires confirmation; consumed time steps are atomically rejected on replay. Five failures trigger a 15-minute account lock. Authentication POSTs are additionally IP rate-limited. Authenticated cookies expire after 15 minutes without sliding refresh. Logout is CSRF-protected POST. Forms and API writes require CSRF tokens. The app applies a restrictive CSP, no-store responses, and secure cookie defaults. Set `SESSION_COOKIE_SECURE=False` only for local HTTP; deploy behind HTTPS with secure cookies enabled. Keep the secret stable, random, and private. Use a shared limiter store for multiple workers; the default in-memory limiter is for single-process local use. SQLite and the Flask development server are academic/local defaults.

Audit events contain event names, account IDs and bounded operational details, never vault contents, login passwords or TOTP codes. The admin view supports manual monitoring; external alert delivery and immutable log shipping are not implemented. The database contains TOTP seeds and must be access-controlled and backed up securely.

## Verification and evidence

```sh
python -m pytest -q --cov=src
node --test tests/vault_crypto.test.cjs
ruff check src tests scripts
bandit -r src
pip-audit -r requirements.txt
```

CI runs these checks, compilation, startup validation, and Gitleaks. Browser screenshots and authorized OWASP ZAP findings must be collected from actual runs; existing evidence placeholders are not claimed as completed evidence. Test coverage includes mandatory TOTP, expiry/replay, account locking, RBAC, CSRF, ownership isolation, strict ciphertext validation, key verification immutability, and deletion. Node runs the same browser encryption functions against Web Crypto to test round trips, wrong keys and tampering.
