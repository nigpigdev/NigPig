"""Passive security checks - headers, cookies, TLS."""

from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

import httpx


@dataclass
class CheckResult:
    """Result of a passive security check."""

    check_name: str
    passed: bool
    severity: str  # info, low, medium, high, critical
    description: str
    details: Optional[str] = None
    remediation: Optional[str] = None


EXPECTED_HEADERS = {
    "Content-Security-Policy": {
        "severity": "medium",
        "description": "Content Security Policy header missing",
        "remediation": "Add a Content-Security-Policy header to prevent XSS attacks",
    },
    "Strict-Transport-Security": {
        "severity": "medium",
        "description": "HSTS header missing",
        "remediation": "Add Strict-Transport-Security header with appropriate max-age",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "X-Frame-Options header missing",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking",
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "description": "X-Content-Type-Options header missing",
        "remediation": "Add X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "Referrer-Policy header missing",
        "remediation": "Add Referrer-Policy header to control referrer information",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "Permissions-Policy header missing",
        "remediation": "Add Permissions-Policy to control browser features",
    },
}

DANGEROUS_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]


async def check_security_headers(
    url: str,
    timeout: int = 10,
) -> list[CheckResult]:
    """Check security headers on a URL.

    Args:
        url: URL to check.
        timeout: Request timeout.

    Returns:
        List of check results.
    """
    results: list[CheckResult] = []

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            headers = response.headers

            # Check for missing security headers
            for header, info in EXPECTED_HEADERS.items():
                present = header.lower() in [h.lower() for h in headers.keys()]
                results.append(
                    CheckResult(
                        check_name=f"header_{header.lower().replace('-', '_')}",
                        passed=present,
                        severity=info["severity"] if not present else "info",
                        description=f"{header} {'present' if present else 'missing'}",
                        details=headers.get(header) if present else None,
                        remediation=info["remediation"] if not present else None,
                    )
                )

            # Check for information disclosure headers
            for header in DANGEROUS_HEADERS:
                if header.lower() in [h.lower() for h in headers.keys()]:
                    results.append(
                        CheckResult(
                            check_name=f"info_disclosure_{header.lower().replace('-', '_')}",
                            passed=False,
                            severity="low",
                            description=f"Information disclosure: {header} header present",
                            details=headers.get(header),
                            remediation=f"Remove or obfuscate the {header} header",
                        )
                    )

    except httpx.RequestError as e:
        results.append(
            CheckResult(
                check_name="connection_error",
                passed=False,
                severity="info",
                description=f"Could not connect to check headers: {e}",
            )
        )

    return results


async def check_cookie_flags(
    url: str,
    timeout: int = 10,
) -> list[CheckResult]:
    """Check cookie security flags.

    Args:
        url: URL to check.
        timeout: Request timeout.

    Returns:
        List of check results.
    """
    results: list[CheckResult] = []

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)

            # Check Set-Cookie headers
            cookies = (
                response.headers.get_list("set-cookie")
                if hasattr(response.headers, "get_list")
                else []
            )
            if not cookies:
                # Try alternative method
                cookies = [
                    v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"
                ]

            for cookie in cookies:
                cookie_lower = cookie.lower()
                cookie_name = cookie.split("=")[0] if "=" in cookie else "unknown"

                # Check HttpOnly
                if "httponly" not in cookie_lower:
                    results.append(
                        CheckResult(
                            check_name="cookie_httponly_missing",
                            passed=False,
                            severity="medium",
                            description=f"Cookie '{cookie_name}' missing HttpOnly flag",
                            details=_mask_cookie_value(cookie),
                            remediation="Add HttpOnly flag to prevent JavaScript access",
                        )
                    )

                # Check Secure flag
                parsed = urlparse(url)
                if parsed.scheme == "https" and "secure" not in cookie_lower:
                    results.append(
                        CheckResult(
                            check_name="cookie_secure_missing",
                            passed=False,
                            severity="medium",
                            description=f"Cookie '{cookie_name}' missing Secure flag",
                            details=_mask_cookie_value(cookie),
                            remediation="Add Secure flag for HTTPS-only transmission",
                        )
                    )

                # Check SameSite
                if "samesite" not in cookie_lower:
                    results.append(
                        CheckResult(
                            check_name="cookie_samesite_missing",
                            passed=False,
                            severity="low",
                            description=f"Cookie '{cookie_name}' missing SameSite attribute",
                            details=_mask_cookie_value(cookie),
                            remediation="Add SameSite=Strict or SameSite=Lax attribute",
                        )
                    )

    except httpx.RequestError as e:
        results.append(
            CheckResult(
                check_name="connection_error",
                passed=False,
                severity="info",
                description=f"Could not connect to check cookies: {e}",
            )
        )

    return results


def _mask_cookie_value(cookie: str) -> str:
    """Mask cookie value for safe logging.

    Args:
        cookie: Full cookie string.

    Returns:
        Masked cookie string.
    """
    if "=" not in cookie:
        return cookie

    parts = cookie.split(";")
    name_value = parts[0]

    if "=" in name_value:
        name, value = name_value.split("=", 1)
        if len(value) > 4:
            masked_value = value[:2] + "*" * (len(value) - 4) + value[-2:]
        else:
            masked_value = "****"
        parts[0] = f"{name}={masked_value}"

    return ";".join(parts)


async def check_tls(url: str) -> list[CheckResult]:
    """Basic TLS check.

    Args:
        url: URL to check.

    Returns:
        List of check results.
    """
    results: list[CheckResult] = []
    parsed = urlparse(url)

    if parsed.scheme != "https":
        results.append(
            CheckResult(
                check_name="tls_not_https",
                passed=False,
                severity="high",
                description="Site is not using HTTPS",
                remediation="Enable HTTPS with a valid TLS certificate",
            )
        )
        return results

    try:
        async with httpx.AsyncClient(timeout=10, verify=True) as client:
            response = await client.get(url)
            results.append(
                CheckResult(
                    check_name="tls_valid",
                    passed=True,
                    severity="info",
                    description="TLS certificate is valid",
                )
            )
    except httpx.ConnectError as e:
        if "certificate" in str(e).lower():
            results.append(
                CheckResult(
                    check_name="tls_invalid_cert",
                    passed=False,
                    severity="high",
                    description="TLS certificate validation failed",
                    details=str(e),
                    remediation="Install a valid TLS certificate from a trusted CA",
                )
            )
        else:
            results.append(
                CheckResult(
                    check_name="tls_connection_error",
                    passed=False,
                    severity="medium",
                    description=f"Could not verify TLS: {e}",
                )
            )

    return results


async def detect_error_patterns(
    url: str,
    timeout: int = 10,
) -> list[CheckResult]:
    """Detect error patterns in response that may leak information.

    Args:
        url: URL to check.
        timeout: Request timeout.

    Returns:
        List of check results.
    """
    results: list[CheckResult] = []

    error_patterns = {
        "stack_trace_java": (
            r"at\s+[\w\.$]+\([\w]+\.java:\d+\)",
            "Java stack trace detected",
        ),
        "stack_trace_python": (
            r"Traceback \(most recent call last\)",
            "Python stack trace detected",
        ),
        "stack_trace_php": (
            r"Stack trace:.*#\d+",
            "PHP stack trace detected",
        ),
        "sql_error": (
            r"(sql syntax|mysql error|ora-\d+|pg_query|sqlite3)",
            "SQL error message detected",
        ),
        "path_disclosure": (
            r"(/var/www/|C:\\inetpub|/home/\w+/)",
            "Server path disclosure detected",
        ),
    }

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            content = response.text.lower()

            import re

            for pattern_name, (pattern, description) in error_patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    results.append(
                        CheckResult(
                            check_name=f"error_pattern_{pattern_name}",
                            passed=False,
                            severity="medium",
                            description=description,
                            details="Error information may leak sensitive details",
                            remediation="Configure custom error pages that don't expose internal details",
                        )
                    )

    except httpx.RequestError:
        pass  # Don't report connection errors for this check

    return results


async def run_all_passive_checks(url: str) -> list[CheckResult]:
    """Run all passive security checks.

    Args:
        url: URL to check.

    Returns:
        Combined list of all check results.
    """
    results: list[CheckResult] = []

    # Run all checks concurrently
    import asyncio

    check_tasks = [
        check_security_headers(url),
        check_cookie_flags(url),
        check_tls(url),
        detect_error_patterns(url),
    ]

    check_results = await asyncio.gather(*check_tasks, return_exceptions=True)

    for result in check_results:
        if isinstance(result, list):
            results.extend(result)
        elif isinstance(result, Exception):
            results.append(
                CheckResult(
                    check_name="check_error",
                    passed=False,
                    severity="info",
                    description=f"Check failed: {result}",
                )
            )

    return results
