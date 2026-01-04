"""Fingerprint API routes - tech and WAF detection."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class TargetRequest(BaseModel):
    url: str


@router.post("/tech")
async def tech_detect(request: TargetRequest):
    """Detect technologies."""
    from nigpig.fingerprint.tech_detect import TechDetector

    detector = TechDetector()
    techs = await detector.detect(request.url)

    return {
        "url": request.url,
        "count": len(techs),
        "technologies": [
            {
                "name": t.name,
                "category": t.category,
                "version": t.version,
                "confidence": t.confidence,
            }
            for t in techs
        ],
    }


@router.post("/waf")
async def waf_detect(request: TargetRequest):
    """Detect WAF."""
    from nigpig.fingerprint.waf_detect import WAFDetector

    detector = WAFDetector()
    wafs = await detector.detect(request.url)

    return {
        "url": request.url,
        "detected": len(wafs) > 0,
        "wafs": [
            {"name": w.name, "confidence": w.confidence, "evidence": w.evidence} for w in wafs
        ],
    }
