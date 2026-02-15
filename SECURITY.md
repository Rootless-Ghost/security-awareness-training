# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Security-Awareness-Training, please report it responsibly:

**DO NOT** open a public GitHub issue for security vulnerabilities.

**How to report:**
- **GitHub Security Advisories**: Use the "Report a vulnerability" button in the Security tab

**What to include in your report:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

**Response timeline:**
- Initial response: Within 48 hours
- Status update: Within 7 days
- Fix timeline: Depends on severity (Critical: 7 days, High: 14 days, Medium: 30 days)

## Security Considerations

### Current Implementation

- Password hashing via Werkzeug (bcrypt)
- Session-based authentication
- SQLite database (development only)
- Localhost-only deployment by default

### Planned Security Improvements

- [ ] CSRF protection (Flask-WTF)
- [ ] Rate limiting (Flask-Limiter)
- [ ] Account lockout after failed login attempts
- [ ] Input validation with WTForms
- [ ] HTTPS enforcement in production
- [ ] Database migration to PostgreSQL for production deployments

## Responsible Use

**CRITICAL:** This platform simulates phishing attacks for **authorized security awareness training only**.

### Acceptable Use

✅ Internal employee security training
✅ Authorized penetration testing exercises
✅ Educational demonstrations with explicit consent
✅ Security awareness campaigns within your organization

### Prohibited Use

❌ Sending phishing simulations to users without authorization
❌ Using against real targets outside your organization
❌ Credential harvesting for malicious purposes
❌ Any activity violating computer fraud laws (CFAA, CMA, etc.)

**Legal Notice:** Unauthorized use of phishing simulation tools may violate federal and state laws. Always obtain written authorization before conducting phishing exercises. The maintainer is not responsible for misuse of this software.

## Deployment Security

When deploying this platform:

1. **Never expose to public internet without proper hardening**
   - Run behind VPN or firewall
   - Implement authentication for all admin endpoints
   - Enable HTTPS with valid certificates

2. **Use environment variables for secrets**
   - Never commit credentials to Git
   - Use `.env` files (already in `.gitignore`)
   - Rotate Flask `SECRET_KEY` regularly

3. **Production database**
   - Migrate from SQLite to PostgreSQL/MySQL
   - Enable database encryption at rest
   - Regular backups with secure storage

4. **Monitor for abuse**
   - Log all phishing campaign sends
   - Track user submissions and credential entries
   - Alert on unusual patterns (high volume, external targets)

## Security Best Practices

- Review generated phishing templates before sending
- Obtain written authorization for all phishing exercises
- Provide immediate debrief after simulations
- Never harvest real credentials (use this for awareness only)
- Comply with your organization's security policies and legal requirements
