"""Secrets module - Detect secrets and sensitive data."""

from nigpig.secrets.patterns import SECRET_PATTERNS, scan_for_secrets
from nigpig.secrets.scanner import SecretScanner, SecretFinding

__all__ = ["SECRET_PATTERNS", "scan_for_secrets", "SecretScanner", "SecretFinding"]
