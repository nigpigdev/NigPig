"""Remediation guidance and OWASP mapping."""

from typing import Any, Optional


# OWASP Top 10 2021 categories
OWASP_TOP_10 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}


# Remediation guidance by finding type/name pattern
REMEDIATION_DB = {
    # XSS related
    "xss": {
        "description": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts.",
        "remediation": "Encode all user input before rendering in HTML. Use Content-Security-Policy headers. Implement context-aware output encoding.",
        "owasp": "A03:2021",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "cross-site scripting": {
        "description": "Cross-Site Scripting (XSS) allows attackers to inject malicious scripts.",
        "remediation": "Encode all user input before rendering in HTML. Use Content-Security-Policy headers. Implement context-aware output encoding.",
        "owasp": "A03:2021",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
        ],
    },
    # SQL Injection
    "sql injection": {
        "description": "SQL Injection allows attackers to manipulate database queries.",
        "remediation": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries. Implement least privilege database access.",
        "owasp": "A03:2021",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "sqli": {
        "description": "SQL Injection allows attackers to manipulate database queries.",
        "remediation": "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
        "owasp": "A03:2021",
        "references": [],
    },
    # Security Headers
    "content-security-policy": {
        "description": "Missing Content-Security-Policy header increases XSS risk.",
        "remediation": "Implement a Content-Security-Policy header with appropriate directives. Start with a restrictive policy and adjust as needed.",
        "owasp": "A05:2021",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
        ],
    },
    "strict-transport-security": {
        "description": "Missing HSTS header allows potential downgrade attacks.",
        "remediation": "Add Strict-Transport-Security header with max-age of at least 31536000 (1 year). Consider includeSubDomains and preload.",
        "owasp": "A05:2021",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        ],
    },
    "x-frame-options": {
        "description": "Missing X-Frame-Options header allows clickjacking attacks.",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN header. Consider using CSP frame-ancestors directive.",
        "owasp": "A05:2021",
        "references": [],
    },
    "x-content-type-options": {
        "description": "Missing X-Content-Type-Options allows MIME sniffing attacks.",
        "remediation": "Add X-Content-Type-Options: nosniff header.",
        "owasp": "A05:2021",
        "references": [],
    },
    # Cookies
    "cookie": {
        "description": "Cookie security flags are missing or misconfigured.",
        "remediation": "Set HttpOnly flag to prevent JavaScript access. Set Secure flag for HTTPS-only transmission. Set SameSite=Strict or Lax to prevent CSRF.",
        "owasp": "A05:2021",
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
        ],
    },
    "httponly": {
        "description": "Cookie missing HttpOnly flag is accessible to JavaScript.",
        "remediation": "Add HttpOnly flag to cookies containing sensitive data.",
        "owasp": "A05:2021",
        "references": [],
    },
    # Information Disclosure
    "information disclosure": {
        "description": "Sensitive information is exposed to users.",
        "remediation": "Remove server version headers. Configure custom error pages. Avoid exposing stack traces or internal paths.",
        "owasp": "A05:2021",
        "references": [],
    },
    "server header": {
        "description": "Server version information is exposed.",
        "remediation": "Configure web server to hide or obfuscate the Server header.",
        "owasp": "A05:2021",
        "references": [],
    },
    "stack trace": {
        "description": "Application stack traces are exposed in error messages.",
        "remediation": "Configure custom error pages. Disable debug mode in production. Log errors server-side only.",
        "owasp": "A05:2021",
        "references": [],
    },
    # TLS/SSL
    "tls": {
        "description": "TLS configuration issues may compromise connection security.",
        "remediation": "Use TLS 1.2 or higher. Disable weak cipher suites. Use strong certificate from trusted CA.",
        "owasp": "A02:2021",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
        ],
    },
    "ssl": {
        "description": "SSL/TLS configuration issues detected.",
        "remediation": "Upgrade to TLS 1.2+. Disable SSLv3 and weak ciphers.",
        "owasp": "A02:2021",
        "references": [],
    },
    "certificate": {
        "description": "TLS certificate issues detected.",
        "remediation": "Use a valid certificate from a trusted Certificate Authority. Ensure certificate is not expired and matches the domain.",
        "owasp": "A02:2021",
        "references": [],
    },
    # CSRF
    "csrf": {
        "description": "Cross-Site Request Forgery allows attackers to perform actions as authenticated users.",
        "remediation": "Implement CSRF tokens for state-changing operations. Use SameSite cookie attribute. Verify Origin/Referer headers.",
        "owasp": "A01:2021",
        "references": [
            "https://owasp.org/www-community/attacks/csrf",
        ],
    },
    # Authentication
    "authentication": {
        "description": "Authentication mechanism vulnerabilities detected.",
        "remediation": "Implement secure password policies. Use multi-factor authentication. Protect against brute force attacks.",
        "owasp": "A07:2021",
        "references": [],
    },
    "session": {
        "description": "Session management issues detected.",
        "remediation": "Generate new session ID after authentication. Set appropriate session timeouts. Invalidate sessions on logout.",
        "owasp": "A07:2021",
        "references": [],
    },
}


def get_remediation_guidance(finding: dict[str, Any]) -> str:
    """Get remediation guidance for a finding.

    Args:
        finding: Finding dictionary.

    Returns:
        Remediation guidance string.
    """
    name = finding.get("name", "").lower()

    # Try to match against known patterns
    for pattern, guidance in REMEDIATION_DB.items():
        if pattern in name:
            return guidance["remediation"]

    # Check for existing remediation/solution
    if finding.get("remediation"):
        return finding["remediation"]
    if finding.get("solution"):
        return finding["solution"]

    # Default guidance
    return "Review the finding details and consult OWASP guidelines for remediation steps."


def map_to_owasp(finding: dict[str, Any]) -> str:
    """Map a finding to OWASP Top 10 category.

    Args:
        finding: Finding dictionary.

    Returns:
        OWASP category string.
    """
    name = finding.get("name", "").lower()

    # Try to match against known patterns
    for pattern, guidance in REMEDIATION_DB.items():
        if pattern in name:
            owasp_id = guidance.get("owasp", "")
            if owasp_id:
                return f"{owasp_id} - {OWASP_TOP_10.get(owasp_id, 'Unknown')}"

    # Default - Security Misconfiguration
    return "A05:2021 - Security Misconfiguration"


def get_full_guidance(finding: dict[str, Any]) -> dict[str, Any]:
    """Get full remediation guidance with references.

    Args:
        finding: Finding dictionary.

    Returns:
        Dictionary with full guidance.
    """
    name = finding.get("name", "").lower()

    for pattern, guidance in REMEDIATION_DB.items():
        if pattern in name:
            return {
                "description": guidance.get("description", ""),
                "remediation": guidance.get("remediation", ""),
                "owasp": guidance.get("owasp", ""),
                "owasp_name": OWASP_TOP_10.get(guidance.get("owasp", ""), ""),
                "references": guidance.get("references", []),
            }

    return {
        "description": finding.get("description", ""),
        "remediation": finding.get("remediation", finding.get("solution", "")),
        "owasp": "A05:2021",
        "owasp_name": "Security Misconfiguration",
        "references": [],
    }
