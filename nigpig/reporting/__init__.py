"""Reporting module - JSON, Markdown, HTML report generation."""

from nigpig.reporting.generator import generate_reports
from nigpig.reporting.remediation import get_remediation_guidance

__all__ = ["generate_reports", "get_remediation_guidance"]
