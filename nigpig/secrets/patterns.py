"""Secret patterns - regex patterns for detecting secrets."""

import re
from dataclasses import dataclass


@dataclass
class SecretPattern:
    """Pattern definition for secret detection."""

    name: str
    pattern: str
    severity: str = "high"
    description: str = ""


# Comprehensive secret patterns (inspired by trufflehog, gitleaks)
SECRET_PATTERNS = [
    # AWS
    SecretPattern(
        name="AWS Access Key ID",
        pattern=r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        severity="critical",
        description="AWS Access Key ID",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]",
        severity="critical",
        description="AWS Secret Access Key",
    ),
    SecretPattern(
        name="AWS MWS Key",
        pattern=r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        severity="critical",
        description="AWS Marketplace Web Service Key",
    ),
    # Google Cloud
    SecretPattern(
        name="Google API Key",
        pattern=r"AIza[0-9A-Za-z\\-_]{35}",
        severity="high",
        description="Google API Key",
    ),
    SecretPattern(
        name="Google OAuth Client ID",
        pattern=r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        severity="medium",
        description="Google OAuth Client ID",
    ),
    SecretPattern(
        name="Google Cloud Service Account",
        pattern=r"\"type\": \"service_account\"",
        severity="critical",
        description="Google Cloud Service Account Key File",
    ),
    # GitHub
    SecretPattern(
        name="GitHub Personal Access Token",
        pattern=r"ghp_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub Personal Access Token",
    ),
    SecretPattern(
        name="GitHub OAuth Access Token",
        pattern=r"gho_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub OAuth Access Token",
    ),
    SecretPattern(
        name="GitHub App Token",
        pattern=r"(ghu|ghs)_[0-9a-zA-Z]{36}",
        severity="critical",
        description="GitHub App Token",
    ),
    SecretPattern(
        name="GitHub Fine-Grained Token",
        pattern=r"github_pat_[0-9a-zA-Z_]{82}",
        severity="critical",
        description="GitHub Fine-Grained Personal Access Token",
    ),
    # GitLab
    SecretPattern(
        name="GitLab Token",
        pattern=r"glpat-[0-9a-zA-Z\\-_]{20}",
        severity="critical",
        description="GitLab Personal Access Token",
    ),
    # Stripe
    SecretPattern(
        name="Stripe Live Secret Key",
        pattern=r"sk_live_[0-9a-zA-Z]{24,99}",
        severity="critical",
        description="Stripe Live Secret Key",
    ),
    SecretPattern(
        name="Stripe Live Publishable Key",
        pattern=r"pk_live_[0-9a-zA-Z]{24,99}",
        severity="medium",
        description="Stripe Live Publishable Key",
    ),
    SecretPattern(
        name="Stripe Test Key",
        pattern=r"(sk|pk)_test_[0-9a-zA-Z]{24,99}",
        severity="low",
        description="Stripe Test Key",
    ),
    # Slack
    SecretPattern(
        name="Slack Token",
        pattern=r"xox[baprs]-([0-9a-zA-Z]{10,48})",
        severity="critical",
        description="Slack Bot/User/App Token",
    ),
    SecretPattern(
        name="Slack Webhook",
        pattern=r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9a-zA-Z]+",
        severity="high",
        description="Slack Webhook URL",
    ),
    # Discord
    SecretPattern(
        name="Discord Bot Token",
        pattern=r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
        severity="critical",
        description="Discord Bot Token",
    ),
    SecretPattern(
        name="Discord Webhook",
        pattern=r"https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+",
        severity="high",
        description="Discord Webhook URL",
    ),
    # Twilio
    SecretPattern(
        name="Twilio Account SID",
        pattern=r"AC[a-zA-Z0-9_\-]{32}",
        severity="high",
        description="Twilio Account SID",
    ),
    SecretPattern(
        name="Twilio Auth Token",
        pattern=r"SK[0-9a-fA-F]{32}",
        severity="critical",
        description="Twilio Auth Token",
    ),
    # SendGrid
    SecretPattern(
        name="SendGrid API Key",
        pattern=r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        severity="critical",
        description="SendGrid API Key",
    ),
    # Mailchimp
    SecretPattern(
        name="Mailchimp API Key",
        pattern=r"[0-9a-f]{32}-us[0-9]{1,2}",
        severity="high",
        description="Mailchimp API Key",
    ),
    # Heroku
    SecretPattern(
        name="Heroku API Key",
        pattern=r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        severity="high",
        description="Heroku API Key (UUID format)",
    ),
    # JWT
    SecretPattern(
        name="JWT Token",
        pattern=r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
        severity="medium",
        description="JSON Web Token",
    ),
    # Private Keys
    SecretPattern(
        name="RSA Private Key",
        pattern=r"-----BEGIN RSA PRIVATE KEY-----",
        severity="critical",
        description="RSA Private Key",
    ),
    SecretPattern(
        name="DSA Private Key",
        pattern=r"-----BEGIN DSA PRIVATE KEY-----",
        severity="critical",
        description="DSA Private Key",
    ),
    SecretPattern(
        name="EC Private Key",
        pattern=r"-----BEGIN EC PRIVATE KEY-----",
        severity="critical",
        description="EC Private Key",
    ),
    SecretPattern(
        name="OpenSSH Private Key",
        pattern=r"-----BEGIN OPENSSH PRIVATE KEY-----",
        severity="critical",
        description="OpenSSH Private Key",
    ),
    SecretPattern(
        name="PGP Private Key",
        pattern=r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        severity="critical",
        description="PGP Private Key Block",
    ),
    # Generic
    SecretPattern(
        name="Generic API Key",
        pattern=r"(?i)(api[_-]?key|apikey|api_secret)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]",
        severity="high",
        description="Generic API Key",
    ),
    SecretPattern(
        name="Generic Secret",
        pattern=r"(?i)(secret|token|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^\s'\"]{8,64})['\"]",
        severity="high",
        description="Generic Secret/Password",
    ),
    SecretPattern(
        name="Database Connection String",
        pattern=r"(?i)(mongodb|postgres|mysql|redis|amqp)://[^\s'\"]+",
        severity="critical",
        description="Database Connection String",
    ),
    # Base64 Encoded Secrets
    SecretPattern(
        name="Base64 Encoded Secret",
        pattern=r"(?i)(password|secret|key|token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40,}={0,2})['\"]?",
        severity="medium",
        description="Possible Base64 Encoded Secret",
    ),
    # Cloud
    SecretPattern(
        name="Azure Storage Key",
        pattern=r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
        severity="critical",
        description="Azure Storage Connection String",
    ),
    SecretPattern(
        name="GCP API Key",
        pattern=r"(?i)(google|gcp|firebase)[_-]?(api[_-]?key|key)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_-]{39})['\"]",
        severity="high",
        description="GCP/Firebase API Key",
    ),
]


def scan_for_secrets(content: str) -> list[dict]:
    """Scan content for secrets using all patterns.

    Args:
        content: Text content to scan.

    Returns:
        List of found secrets with details.
    """
    findings = []
    seen = set()

    for pattern_def in SECRET_PATTERNS:
        try:
            matches = re.finditer(pattern_def.pattern, content, re.MULTILINE)
            for match in matches:
                # Get the matched value
                value = match.group(1) if match.groups() else match.group(0)

                # Skip duplicates
                if value in seen:
                    continue
                seen.add(value)

                # Find line number
                line_num = content[: match.start()].count("\n") + 1

                # Get context (surrounding text)
                start = max(0, match.start() - 20)
                end = min(len(content), match.end() + 20)
                context = content[start:end].replace("\n", " ").strip()

                findings.append(
                    {
                        "type": pattern_def.name,
                        "value": value[:50] + "..." if len(value) > 50 else value,
                        "severity": pattern_def.severity,
                        "line": line_num,
                        "context": context[:80],
                        "description": pattern_def.description,
                    }
                )
        except Exception:
            continue

    return findings
