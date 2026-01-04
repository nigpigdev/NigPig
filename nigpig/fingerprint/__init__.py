"""Fingerprint module - Technology, WAF, and CMS detection."""

from nigpig.fingerprint.tech_detect import TechDetector, TechResult
from nigpig.fingerprint.waf_detect import WAFDetector, WAFResult

__all__ = ["TechDetector", "TechResult", "WAFDetector", "WAFResult"]
