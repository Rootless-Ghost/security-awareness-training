# Security Considerations

## Current Implementation
- Password hashing via Werkzeug
- Session-based authentication
- SQLite database (dev only)

## Planned Improvements
- [ ] CSRF protection (Flask-WTF)
- [ ] Rate limiting (Flask-Limiter)
- [ ] Account lockout after failed attempts
- [ ] Input validation with WTForms
- [ ] HTTPS enforcement in production

## Responsible Use
This platform simulates phishing for **authorized training only**.
Do not use against real users without explicit written permission.

## Reporting Issues
If you find a security vulnerability, please open a private issue or contact the maintainer directly.
