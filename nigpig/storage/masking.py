"""Sensitive data masking for storage and reporting."""

import re
from typing import Any


# Patterns to mask in evidence and logs
MASK_PATTERNS = [
    # Authorization headers
    (r"(Authorization:\s*(?:Bearer|Basic|Digest)\s+)[^\s\r\n]+", r"\1[REDACTED]"),
    # Cookies
    (r"(Cookie:\s*)[^\r\n]+", r"\1[REDACTED]"),
    (r"(Set-Cookie:\s*)[^\r\n]+", r"\1[REDACTED]"),
    # Session tokens
    (r'(session[_-]?(?:id|token)?[=:]\s*)[^\s&"\']+', r"\1[REDACTED]", re.IGNORECASE),
    (r'(csrf[_-]?token[=:]\s*)[^\s&"\']+', r"\1[REDACTED]", re.IGNORECASE),
    # API keys
    (r'(api[_-]?key[=:]\s*)[^\s&"\']+', r"\1[REDACTED]", re.IGNORECASE),
    (r'(secret[_-]?key[=:]\s*)[^\s&"\']+', r"\1[REDACTED]", re.IGNORECASE),
    (r'(access[_-]?token[=:]\s*)[^\s&"\']+', r"\1[REDACTED]", re.IGNORECASE),
    # Passwords
    (r'(password[=:]\s*)[^\s&"\']+', r"\1[REDACTED]", re.IGNORECASE),
    (r'(passwd[=:]\s*)[^\s&"\']+', r"\1[REDACTED]", re.IGNORECASE),
    (r'(pwd[=:]\s*)[^\s&"\']+', r"\1[REDACTED]", re.IGNORECASE),
]

# PII patterns
PII_PATTERNS = [
    # Email addresses
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "[EMAIL]"),
    # Phone numbers (various formats)
    (r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", "[PHONE]"),
    (r"\b\+\d{1,3}[-.\s]?\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b", "[PHONE]"),
    # SSN
    (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN]"),
    # Credit card numbers
    (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "[CARD]"),
    # IP addresses (internal/private only for extra caution)
    (r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b", "[INTERNAL_IP]"),
]


def mask_sensitive_data(
    data: dict[str, Any],
    mask_pii: bool = True,
) -> dict[str, Any]:
    """Mask sensitive data in a dictionary.

    Recursively processes all string values in the dictionary.

    Args:
        data: Dictionary to mask.
        mask_pii: Whether to also mask PII patterns.

    Returns:
        Dictionary with masked values.
    """
    result: dict[str, Any] = {}

    for key, value in data.items():
        if isinstance(value, str):
            result[key] = mask_string(value, mask_pii)
        elif isinstance(value, dict):
            result[key] = mask_sensitive_data(value, mask_pii)
        elif isinstance(value, list):
            result[key] = [
                mask_sensitive_data(item, mask_pii)
                if isinstance(item, dict)
                else mask_string(item, mask_pii)
                if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def mask_string(text: str, mask_pii: bool = True) -> str:
    """Mask sensitive data in a string.

    Args:
        text: String to mask.
        mask_pii: Whether to also mask PII patterns.

    Returns:
        Masked string.
    """
    result = text

    # Apply security patterns
    for pattern_tuple in MASK_PATTERNS:
        if len(pattern_tuple) == 2:
            pattern, replacement = pattern_tuple
            flags = 0
        else:
            pattern, replacement, flags = pattern_tuple

        result = re.sub(pattern, replacement, result, flags=flags)

    # Apply PII patterns
    if mask_pii:
        for pattern, replacement in PII_PATTERNS:
            result = re.sub(pattern, replacement, result)

    return result


def mask_url_params(url: str) -> str:
    """Mask potentially sensitive query parameters.

    Args:
        url: URL to mask.

    Returns:
        URL with masked sensitive parameters.
    """
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    sensitive_params = {
        "token",
        "key",
        "secret",
        "password",
        "pwd",
        "pass",
        "api_key",
        "apikey",
        "access_token",
        "auth",
        "session",
        "csrf",
        "csrf_token",
        "nonce",
    }

    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        masked_params = {}
        for key, values in params.items():
            if key.lower() in sensitive_params:
                masked_params[key] = ["[REDACTED]"]
            else:
                masked_params[key] = values

        new_query = urlencode(masked_params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    except Exception:
        return url


def mask_headers(headers: dict[str, str]) -> dict[str, str]:
    """Mask sensitive HTTP headers.

    Args:
        headers: HTTP headers dictionary.

    Returns:
        Headers with sensitive values masked.
    """
    sensitive_headers = {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
    }

    result = {}
    for name, value in headers.items():
        if name.lower() in sensitive_headers:
            result[name] = "[REDACTED]"
        else:
            result[name] = value

    return result
