"""Secrets API routes - secret detection."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class ContentRequest(BaseModel):
    content: str
    source: str = "inline"


class PathRequest(BaseModel):
    path: str
    recursive: bool = True


@router.post("/scan/content")
async def scan_content(request: ContentRequest):
    """Scan content for secrets."""
    from nigpig.secrets.scanner import SecretScanner

    scanner = SecretScanner()
    findings = await scanner.scan_content(request.content, request.source)

    return {
        "source": request.source,
        "findings_count": len(findings),
        "findings": [
            {
                "type": f.secret_type,
                "value": f.value,
                "severity": f.severity,
                "line": f.line,
                "context": f.context,
            }
            for f in findings
        ],
    }


@router.post("/scan/path")
async def scan_path(request: PathRequest):
    """Scan path for secrets."""
    from pathlib import Path
    from nigpig.secrets.scanner import SecretScanner

    path = Path(request.path)
    if not path.exists():
        return {"error": "Path not found"}

    scanner = SecretScanner()
    findings = []

    if path.is_file():
        findings = await scanner.scan_file(path)
    else:
        async for finding in scanner.scan_directory(path, recursive=request.recursive):
            findings.append(finding)

    return {
        "path": str(path),
        "findings_count": len(findings),
        "findings": [
            {
                "file": f.file_path,
                "type": f.secret_type,
                "value": f.value,
                "severity": f.severity,
                "line": f.line,
            }
            for f in findings
        ],
    }


@router.get("/patterns")
async def list_patterns():
    """List secret patterns."""
    from nigpig.secrets.patterns import SECRET_PATTERNS

    return {
        "count": len(SECRET_PATTERNS),
        "patterns": [
            {"name": p.name, "severity": p.severity, "description": p.description}
            for p in SECRET_PATTERNS
        ],
    }
