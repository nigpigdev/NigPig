"""Dashboard routes."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/api/dashboard")
async def dashboard_stats():
    """Get dashboard statistics."""
    return {
        "total_scans": 0,
        "vulnerabilities_found": 0,
        "subdomains_discovered": 0,
        "technologies_detected": 0,
    }
