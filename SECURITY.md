# Security Policy

## Supported Versions

This project is an academic prototype and is subject to evaluation in a local or authorized lab environment.

## Reporting Security Issues

Please do not disclose security vulnerabilities publicly before they are addressed. Report them privately to the project maintainers.

Use a secure communication channel and include:
- summary of the issue
- affected component
- reproduction steps
- potential impact
- suggested mitigation

## Security Expectations

- Do not commit `.env` or secrets
- Do not store plaintext passwords or vault secrets
- Do not expose stack traces in production
- Follow authorization checks on the server side
- Validate input and sanitize output
- Keep dependencies updated and scanned
