"""Tests for report generation."""

import pytest
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from nigpig.reporting.generator import (
    generate_markdown_report,
    generate_html_report,
    generate_reports,
)
from nigpig.reporting.remediation import (
    get_remediation_guidance,
    map_to_owasp,
)


class TestRemediationGuidance:
    """Tests for remediation guidance lookup."""

    def test_xss_remediation(self):
        """Test XSS finding gets appropriate remediation."""
        finding = {"name": "Cross-Site Scripting (XSS)"}
        guidance = get_remediation_guidance(finding)
        assert "XSS" in guidance or "encode" in guidance.lower()

    def test_sql_injection_remediation(self):
        """Test SQL injection finding gets appropriate remediation."""
        finding = {"name": "SQL Injection"}
        guidance = get_remediation_guidance(finding)
        assert "parameterized" in guidance.lower() or "prepared" in guidance.lower()

    def test_csp_remediation(self):
        """Test CSP header finding gets appropriate remediation."""
        finding = {"name": "Missing Content-Security-Policy header"}
        guidance = get_remediation_guidance(finding)
        assert "Content-Security-Policy" in guidance

    def test_fallback_remediation(self):
        """Test fallback for unknown finding types."""
        finding = {"name": "Unknown Finding Type ABC123"}
        guidance = get_remediation_guidance(finding)
        assert len(guidance) > 0  # Should return something


class TestOwaspMapping:
    """Tests for OWASP Top 10 mapping."""

    def test_xss_maps_to_injection(self):
        """Test XSS maps to A03 Injection."""
        finding = {"name": "Cross-Site Scripting"}
        mapping = map_to_owasp(finding)
        assert "A03" in mapping

    def test_sql_injection_maps_to_injection(self):
        """Test SQL injection maps to A03 Injection."""
        finding = {"name": "SQL Injection vulnerability"}
        mapping = map_to_owasp(finding)
        assert "A03" in mapping

    def test_header_maps_to_misconfiguration(self):
        """Test security headers map to A05 Security Misconfiguration."""
        finding = {"name": "X-Frame-Options header missing"}
        mapping = map_to_owasp(finding)
        assert "A05" in mapping


class TestMarkdownReportGeneration:
    """Tests for Markdown report generation."""

    @pytest.fixture
    def sample_data(self):
        """Return sample report data."""
        return {
            "run_info": {
                "target": "https://example.com",
                "run_id": "test_run_001",
                "start_time": "2024-01-01T00:00:00",
                "end_time": "2024-01-01T00:30:00",
            },
            "findings": [
                {
                    "name": "XSS Vulnerability",
                    "severity": "high",
                    "description": "Cross-site scripting found",
                    "url": "https://example.com/search",
                    "param": "q",
                    "remediation_guidance": "Encode output",
                    "owasp_mapping": "A03:2021",
                },
                {
                    "name": "Missing HSTS",
                    "severity": "medium",
                    "description": "HSTS header not set",
                    "remediation_guidance": "Add HSTS header",
                    "owasp_mapping": "A05:2021",
                },
            ],
            "severity_summary": {
                "critical": 0,
                "high": 1,
                "medium": 1,
                "low": 0,
                "info": 0,
            },
            "total_findings": 2,
            "generated_at": "2024-01-01T00:30:00",
        }

    def test_markdown_contains_target(self, sample_data):
        """Test that Markdown report contains target URL."""
        md = generate_markdown_report(sample_data)
        assert "https://example.com" in md

    def test_markdown_contains_findings(self, sample_data):
        """Test that Markdown report contains findings."""
        md = generate_markdown_report(sample_data)
        assert "XSS Vulnerability" in md
        assert "Missing HSTS" in md

    def test_markdown_contains_severity_table(self, sample_data):
        """Test that Markdown report contains severity summary."""
        md = generate_markdown_report(sample_data)
        assert "Critical" in md
        assert "High" in md


class TestHtmlReportGeneration:
    """Tests for HTML report generation."""

    @pytest.fixture
    def sample_data(self):
        """Return sample report data."""
        return {
            "run_info": {
                "target": "https://example.com",
                "run_id": "test_run_001",
                "start_time": "2024-01-01T00:00:00",
                "end_time": "2024-01-01T00:30:00",
            },
            "findings": [
                {
                    "name": "Test Finding",
                    "severity": "high",
                    "description": "Test description",
                },
            ],
            "severity_summary": {
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "total_findings": 1,
            "generated_at": "2024-01-01T00:30:00",
        }

    def test_html_is_valid(self, sample_data):
        """Test that HTML report is valid HTML."""
        html = generate_html_report(sample_data)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_html_contains_styles(self, sample_data):
        """Test that HTML report contains CSS styles."""
        html = generate_html_report(sample_data)
        assert "<style>" in html
        assert "</style>" in html


class TestFullReportGeneration:
    """Tests for full report generation (all formats)."""

    @pytest.mark.asyncio
    async def test_generate_all_formats(self):
        """Test that all report formats are generated."""
        findings = [
            {"name": "Test Finding", "severity": "medium"},
        ]
        run_info = {
            "target": "https://example.com",
            "run_id": "test_001",
            "start_time": "2024-01-01T00:00:00",
            "end_time": "2024-01-01T00:30:00",
        }

        with TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir)
            await generate_reports(findings, run_info, output_dir)

            # Check all files exist
            assert (output_dir / "report.json").exists()
            assert (output_dir / "report.md").exists()
            assert (output_dir / "report.html").exists()

            # Verify JSON is valid
            with open(output_dir / "report.json") as f:
                data = json.load(f)
                assert "findings" in data
                assert "run_info" in data
