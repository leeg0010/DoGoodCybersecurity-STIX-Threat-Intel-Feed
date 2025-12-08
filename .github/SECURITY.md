# Security Policy

## Reporting Security Vulnerabilities

**Do NOT report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in this threat intelligence feed or related infrastructure, please report it responsibly:

### Private Disclosure Process

1. **Email**: Send details to lee@dogoodcybersecurity.com
2. **Encryption**: PGP key available upon request
3. **Subject Line**: Include "SECURITY" in the subject
4. **Details**: Provide as much information as possible:
   - Type of issue (false positive, data exposure, infrastructure vulnerability, etc.)
   - Affected components or data
   - Steps to reproduce
   - Potential impact
   - Suggested remediation (if any)

### What to Report

We appreciate reports of:
- **False Positives**: Legitimate IPs incorrectly flagged as malicious
- **Data Quality Issues**: Incorrect ASN, geographic data, or confidence scores
- **Privacy Concerns**: Accidental exposure of sensitive information
- **Infrastructure Vulnerabilities**: Issues with generation scripts or automation
- **Feed Integrity**: Malformed STIX objects or broken references

### What NOT to Report

The following are NOT security vulnerabilities:
- IPs that appear in the feed (this is public threat intel)
- Honeypot infrastructure discovery (they are intentionally exposed)
- Attack attempts against the honeypots (that's their purpose)
- Differences in opinion on indicator quality or confidence scores

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution**: Variable depending on severity and complexity
- **Public Disclosure**: Coordinated with reporter after fix deployment

### Scope

This security policy applies to:
- STIX feed generation scripts
- GitHub Actions workflows
- Feed data quality and accuracy
- Infrastructure security (where applicable)

This policy does NOT cover:
- Third-party consumption of the feed (your responsibility)
- Honeypot infrastructure (intentionally exposed)
- Source Elasticsearch cluster (not public-facing)

### Safe Harbor

We support safe harbor for security researchers:
- Good faith security research is welcomed
- We will not pursue legal action for responsible disclosure
- Public disclosure should be coordinated with our team
- Respect privacy and avoid unnecessary data collection

### Recognition

We maintain a Hall of Fame for security researchers who responsibly disclose issues:
- Public acknowledgment (with permission)
- Listed in repository SECURITY.md
- Credit in relevant changelog entries

Thank you for helping keep this threat intelligence feed secure and reliable!

---

**Last Updated**: December 8, 2025  
**Contact**: lee@dogoodcybersecurity.com  
**PGP Key**: Available upon request
