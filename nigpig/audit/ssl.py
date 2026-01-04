"""SSL/TLS analysis - certificate and configuration checks."""

import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse


@dataclass
class CertificateInfo:
    """SSL certificate information."""

    subject: dict[str, str]
    issuer: dict[str, str]
    version: int
    serial_number: str
    not_before: datetime
    not_after: datetime
    subject_alt_names: list[str] = field(default_factory=list)
    is_expired: bool = False
    days_until_expiry: int = 0


@dataclass
class SSLResult:
    """Result of SSL/TLS analysis."""

    host: str
    port: int = 443
    protocol: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    certificate: CertificateInfo | None = None
    supports_tls_1_0: bool = False
    supports_tls_1_1: bool = False
    supports_tls_1_2: bool = False
    supports_tls_1_3: bool = False
    has_hsts: bool = False
    hsts_max_age: int = 0
    issues: list[str] = field(default_factory=list)
    score: str = "A"  # A, B, C, D, F


class SSLAnalyzer:
    """Analyze SSL/TLS configuration."""

    def __init__(self, timeout: float = 10.0):
        """Initialize SSL analyzer.

        Args:
            timeout: Connection timeout.
        """
        self.timeout = timeout

    def analyze(self, host: str, port: int = 443) -> SSLResult:
        """Analyze SSL/TLS configuration of a host.

        Args:
            host: Hostname to analyze.
            port: Port number.

        Returns:
            SSLResult with analysis.
        """
        # Extract host from URL if needed
        if "://" in host:
            parsed = urlparse(host)
            host = parsed.hostname or host
            port = parsed.port or port

        result = SSLResult(host=host, port=port)

        try:
            # Get certificate and connection info
            context = ssl.create_default_context()

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get protocol and cipher
                    result.protocol = ssock.version() or ""
                    cipher_info = ssock.cipher()
                    if cipher_info:
                        result.cipher = cipher_info[0]
                        result.cipher_bits = cipher_info[2]

                    # Get certificate
                    cert = ssock.getpeercert()
                    if cert:
                        result.certificate = self._parse_certificate(cert)

            # Check protocol versions
            result.supports_tls_1_0 = self._check_protocol(host, port, ssl.TLSVersion.TLSv1)
            result.supports_tls_1_1 = self._check_protocol(host, port, ssl.TLSVersion.TLSv1_1)
            result.supports_tls_1_2 = self._check_protocol(host, port, ssl.TLSVersion.TLSv1_2)
            result.supports_tls_1_3 = self._check_protocol(host, port, ssl.TLSVersion.TLSv1_3)

            # Check issues
            result.issues = self._check_issues(result)

            # Calculate score
            result.score = self._calculate_score(result)

        except Exception as e:
            result.issues.append(f"Connection error: {str(e)}")
            result.score = "F"

        return result

    def _parse_certificate(self, cert: dict) -> CertificateInfo:
        """Parse certificate dictionary.

        Args:
            cert: Certificate dict from getpeercert().

        Returns:
            CertificateInfo.
        """
        # Parse subject
        subject = {}
        for item in cert.get("subject", ()):
            for key, value in item:
                subject[key] = value

        # Parse issuer
        issuer = {}
        for item in cert.get("issuer", ()):
            for key, value in item:
                issuer[key] = value

        # Parse dates
        date_format = "%b %d %H:%M:%S %Y %Z"
        not_before = datetime.strptime(cert.get("notBefore", ""), date_format)
        not_after = datetime.strptime(cert.get("notAfter", ""), date_format)

        # Parse SANs
        sans = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                sans.append(san_value)

        # Check expiry
        now = datetime.now()
        is_expired = now > not_after
        days_until_expiry = (not_after - now).days

        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            version=cert.get("version", 0),
            serial_number=str(cert.get("serialNumber", "")),
            not_before=not_before,
            not_after=not_after,
            subject_alt_names=sans,
            is_expired=is_expired,
            days_until_expiry=days_until_expiry,
        )

    def _check_protocol(
        self,
        host: str,
        port: int,
        version: ssl.TLSVersion,
    ) -> bool:
        """Check if a TLS version is supported.

        Args:
            host: Hostname.
            port: Port.
            version: TLS version to check.

        Returns:
            True if supported.
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = version
            context.maximum_version = version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return True
        except Exception:
            return False

    def _check_issues(self, result: SSLResult) -> list[str]:
        """Check for SSL/TLS issues.

        Args:
            result: SSLResult to check.

        Returns:
            List of issue descriptions.
        """
        issues = []

        # Certificate issues
        if result.certificate:
            if result.certificate.is_expired:
                issues.append("Certificate is expired")
            elif result.certificate.days_until_expiry < 30:
                issues.append(f"Certificate expires in {result.certificate.days_until_expiry} days")

        # Protocol issues
        if result.supports_tls_1_0:
            issues.append("TLS 1.0 is supported (deprecated)")
        if result.supports_tls_1_1:
            issues.append("TLS 1.1 is supported (deprecated)")
        if not result.supports_tls_1_2 and not result.supports_tls_1_3:
            issues.append("Neither TLS 1.2 nor 1.3 is supported")

        # Cipher issues
        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT"]
        if result.cipher:
            for weak in weak_ciphers:
                if weak in result.cipher.upper():
                    issues.append(f"Weak cipher in use: {result.cipher}")
                    break

        if result.cipher_bits and result.cipher_bits < 128:
            issues.append(f"Weak cipher strength: {result.cipher_bits} bits")

        return issues

    def _calculate_score(self, result: SSLResult) -> str:
        """Calculate SSL security score.

        Args:
            result: SSLResult.

        Returns:
            Grade A-F.
        """
        score = 100

        if result.certificate and result.certificate.is_expired:
            score -= 50

        if result.supports_tls_1_0:
            score -= 20
        if result.supports_tls_1_1:
            score -= 10

        if not result.supports_tls_1_3:
            score -= 5

        if result.cipher_bits and result.cipher_bits < 128:
            score -= 30

        score -= len(result.issues) * 5

        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        return "F"

    async def analyze_async(self, host: str, port: int = 443) -> SSLResult:
        """Async wrapper for analyze.

        Args:
            host: Hostname.
            port: Port.

        Returns:
            SSLResult.
        """
        import asyncio

        return await asyncio.to_thread(self.analyze, host, port)


def quick_ssl_check(url: str) -> SSLResult:
    """Quick SSL check for a URL.

    Args:
        url: URL or hostname.

    Returns:
        SSLResult.
    """
    analyzer = SSLAnalyzer()
    return analyzer.analyze(url)
