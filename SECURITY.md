# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Enterprise Council AI takes security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **Email**: Send a detailed report to [security@council.ai](mailto:security@council.ai).
2. **Do NOT** open a public GitHub issue for security vulnerabilities.
3. Include the following in your report:
   - Description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Suggested fix (if any)

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Acknowledgement of report | Within 48 hours |
| Initial assessment | Within 5 business days |
| Patch release (critical) | Within 7 business days |
| Patch release (non-critical) | Within 30 business days |

### Security Measures Implemented

- **Input Sanitization**: All user inputs are sanitized using alphanumeric regex (`re.sub(r'[^\w\s\-]', '', text)`) to prevent SPL and SQL injection attacks.
- **Rate Limiting**: API endpoints are protected with SlowAPI rate limiting (10 requests/minute per IP).
- **HTTP Security Headers**: Strict security headers applied via FastAPI middleware:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `Content-Security-Policy: default-src 'self'`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- **Session Timeout**: Active client-side session monitoring locks the interface after 30 minutes of inactivity.
- **Credential Redaction**: Sensitive configuration values are masked using password-type inputs in the UI.
- **CORS Policy**: Cross-origin requests are restricted to authorized deployment origins only.
- **HTTPS Enforcement**: Optional HTTPS redirect middleware activates when SSL certificates are present.

### Scope

The following components are in scope for security reports:

| Component | In Scope |
|-----------|----------|
| FastAPI REST endpoints (`api/`) | ✅ |
| Streamlit frontend (`frontend/`) | ✅ |
| Splunk query interfaces (`splunk/`) | ✅ |
| MCP protocol layer (`mcp/`) | ✅ |
| Landing page (`index.html`) | ✅ |
| Digital Twin graph model (`twin/`) | ✅ |
| Third-party dependencies | ⚠️ Partial |

### Disclosure Policy

We follow [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure). We ask that you:

- Allow us reasonable time to address the vulnerability before public disclosure.
- Make a good faith effort to avoid privacy violations, data destruction, and service interruption.
- Do not access or modify data belonging to other users.

## Acknowledgements

We appreciate the security research community's efforts to improve the security of Enterprise Council AI. Researchers who report valid vulnerabilities will be acknowledged in this section (with their permission).
