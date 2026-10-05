# SecureVault: Zero-Knowledge Password Security and Encrypted Vault Management System

SecureVault is an academic cybersecurity project developed for ICT932 – Cybersecurity Testing and Assurance. The system demonstrates password security, encrypted vault management, two-factor authentication, session controls, RBAC, audit logging, and DevSecOps security testing in a Flask web application.

This project is a zero-knowledge-style academic prototype designed for learning and demonstration. It stores encrypted vault records rather than plaintext secrets and treats the server as an untrusted storage layer for ciphertext. However, this is not a formally verified zero-knowledge cryptographic protocol and should not be interpreted as a production-grade cryptographic system.

## Overview

The application provides:
- secure registration and login
- Argon2id password hashing
- TOTP-based 2FA
- role-based access control
- secure session timeout
- browser-side cryptographic password generation and minimum passphrase length checks
- encrypted vault storage using AES-256-GCM
- audit logging for security events
- CI/CD and security testing automation

## Problem

Users commonly reuse weak passwords, store secrets in plaintext, and expose credentials to password management systems with insufficient protection. Academic environments require practical demonstrations of secure design patterns, defensive coding, and verification workflows.

## Objectives

- implement secure user authentication and authorization
- demonstrate encrypted vault storage with authenticated encryption
- enforce access controls and session controls
- show secure logging and auditability
- integrate automated security testing in CI/CD
- provide a realistic but educational cybersecurity project

## Architecture

The app follows a layered architecture:
- browser client with HTTPS
- Flask application with auth, vault, and admin modules
- SQLite database for persistence
- crypto layer using AES-256-GCM for vault secrets
- audit and monitoring layer for security events

## Security Controls

- Argon2id password hashing
- AES-256-GCM authenticated encryption
- TOTP 2FA
- CSRF protection for forms
- secure cookie settings
- automatic session timeout
- rate limiting for authentication attempts
- server-side authorization checks
- sanitized and audited security events
- dependency and secret scanning in CI/CD

## Zero-Knowledge-style Architecture

This project stores only ciphertext and metadata in the database. The server is not expected to possess plaintext vault values, and each vault entry is encrypted before persistence. This is a zero-knowledge-style design for learning and academic demonstration, but it is not a formally verified zero-knowledge proof system or cryptographic protocol.

## Repository Structure

- src/ – application source code
- tests/ – pytest test suite
- docs/ – architecture, threat model, security testing, and incident response documentation
- ci-cd/ – CI/CD notes
- .github/workflows/ – GitHub Actions pipeline
- scripts/ – database initialization scripts

## Implemented MVP

See [MVP operations and threat model](docs/MVP.md) for the implemented flows, security boundaries, testing, and database compatibility. Python 3.14 and Node 24 are the validated runtimes. Use a separate master passphrase: it is never sent to the server. Labels, usernames, and passwords are encrypted in the browser. No server-side AES vault key is used.

## Installation

1. Clone the repository
2. Create a virtual environment
3. Install dependencies
4. Configure environment variables
5. Initialize the database
6. Run the app

```bash
python3.14 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Generate a secret and paste it into SECRET_KEY in .env:
python -c "import secrets; print(secrets.token_hex(32))"
python scripts/init_db.py
python src/app.py
```

## Environment Setup

The project uses environment variables defined in `.env`.

Example:

```env
SECRET_KEY=PASTE_A_RANDOM_64_CHARACTER_HEX_VALUE
DATABASE_URL=sqlite:///securevault.db
SESSION_COOKIE_SECURE=False
APP_ENV=development
```

Do not commit `.env` or any private key material.

## Database Initialization

```bash
python scripts/init_db.py
```

## Running Instructions

```bash
python -m flask --app src.app run
```

Or directly:

```bash
python src/app.py
```

## Testing Instructions

```bash
pytest -q
```

## Security Testing Instructions

```bash
bandit -r src
pytest -q
pip-audit
```

## GitHub Actions Explanation

The repository includes a security-focused GitHub Actions workflow in `.github/workflows/security.yml` that runs:
- checkout
- Python setup
- dependency installation
- linting
- static application security testing
- unit tests
- dependency vulnerability scanning
- secret scanning
- build/startup validation

The pipeline is configured to fail when serious issues are detected.

## Ethical Testing Statement

This project is intended for local or explicitly authorized lab environments only. Testing must not target systems without appropriate permission. The security testing documentation applies to this project and other authorized lab environments only.

## Limitations

This is an academic prototype and not a production-certified zero-knowledge system. It demonstrates secure patterns and encryption use while keeping the implementation understandable for learning and assessment.

## Team Member Responsibilities

- Banish Kumar Sapkota — Student ID: CIHE250
- Manjil Khanal — Student ID: CIHE250

## Academic Evidence Placeholders

[INSERT SCREENSHOT: GitHub Repository]
[INSERT SCREENSHOT: GitHub Commit History]
[INSERT SCREENSHOT: Login Page]
[INSERT SCREENSHOT: 2FA Setup]
[INSERT SCREENSHOT: User Dashboard]
[INSERT SCREENSHOT: Encrypted Vault]
[INSERT SCREENSHOT: Database Ciphertext]
[INSERT SCREENSHOT: Admin Dashboard]
[INSERT SCREENSHOT: Audit Log]
[INSERT SCREENSHOT: GitHub Actions Pipeline]
[INSERT SCREENSHOT: Bandit Result]
[INSERT SCREENSHOT: Gitleaks Result]
[INSERT SCREENSHOT: pip-audit Result]
[INSERT SCREENSHOT: OWASP ZAP Result]
[INSERT SCREENSHOT: Vulnerability Before Remediation]
[INSERT SCREENSHOT: Successful Re-test]
