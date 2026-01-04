"""Audit API routes - SSL and dependency scanning."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class SSLRequest(BaseModel):
    url: str
    port: int = 443


class DepRequest(BaseModel):
    path: str


@router.post("/ssl")
async def ssl_analyze(request: SSLRequest):
    """Analyze SSL/TLS configuration."""
    from nigpig.audit.ssl import SSLAnalyzer

    analyzer = SSLAnalyzer()
    result = await analyzer.analyze_async(request.url, request.port)

    cert_info = None
    if result.certificate:
        cert_info = {
            "subject": result.certificate.subject,
            "issuer": result.certificate.issuer,
            "not_after": result.certificate.not_after.isoformat(),
            "days_until_expiry": result.certificate.days_until_expiry,
            "is_expired": result.certificate.is_expired,
        }

    return {
        "host": result.host,
        "port": result.port,
        "grade": result.score,
        "protocol": result.protocol,
        "cipher": result.cipher,
        "cipher_bits": result.cipher_bits,
        "certificate": cert_info,
        "supports": {
            "tls_1_0": result.supports_tls_1_0,
            "tls_1_1": result.supports_tls_1_1,
            "tls_1_2": result.supports_tls_1_2,
            "tls_1_3": result.supports_tls_1_3,
        },
        "issues": result.issues,
    }


@router.post("/deps")
async def dep_scan(request: DepRequest):
    """Scan dependencies for vulnerabilities."""
    from pathlib import Path
    from nigpig.audit.deps import DependencyScanner

    path = Path(request.path)
    if not path.exists():
        return {"error": "Path not found"}

    scanner = DependencyScanner()
    results = await scanner.scan_all(path)

    formatted = {}
    for lang, vulns in results.items():
        formatted[lang] = [
            {
                "name": v.name,
                "version": v.version,
                "vulnerability_id": v.vulnerability_id,
                "severity": v.severity,
                "description": v.description,
                "fixed_version": v.fixed_version,
            }
            for v in vulns
        ]

    total = sum(len(v) for v in results.values())

    return {
        "path": str(path),
        "total_vulnerabilities": total,
        "by_language": formatted,
    }
