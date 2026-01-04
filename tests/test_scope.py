"""Tests for scope validation."""

import pytest

from nigpig.safety.scope import ScopeValidator


class TestScopeValidator:
    """Tests for ScopeValidator."""

    @pytest.fixture
    def default_config(self):
        """Return default config for testing."""
        return {
            "scope": {
                "same_origin_only": True,
                "respect_robots_txt": False,  # Disable for unit tests
                "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                "blocked_methods": ["PUT", "DELETE", "PATCH", "POST"],
            },
            "rate_limits": {
                "requests_per_second": 10,
                "max_concurrency": 5,
                "max_urls": 100,
            },
        }

    @pytest.fixture
    def validator(self, default_config):
        """Return a ScopeValidator instance."""
        return ScopeValidator(
            target="https://example.com",
            config=default_config,
            ignore_robots=True,
        )

    def test_same_origin_in_scope(self, validator):
        """Test that same-origin URLs are in scope."""
        assert validator.is_in_scope("https://example.com/path")
        assert validator.is_in_scope("https://example.com/other/path")
        assert validator.is_in_scope("https://example.com/api/v1/users")

    def test_different_origin_out_of_scope(self, validator):
        """Test that different-host URLs are out of scope."""
        assert not validator.is_in_scope("https://other.com/path")
        assert not validator.is_in_scope("https://sub.example.com/path")  # Subdomain
        # Note: Same host with different scheme is IN scope (we check host, not full origin)
        assert validator.is_in_scope("http://example.com/path")

    def test_allowed_methods(self, validator):
        """Test allowed HTTP methods."""
        assert validator.is_method_allowed("GET")
        assert validator.is_method_allowed("HEAD")
        assert validator.is_method_allowed("OPTIONS")
        assert validator.is_method_allowed("get")  # Case insensitive

    def test_blocked_methods(self, validator):
        """Test blocked HTTP methods."""
        assert not validator.is_method_allowed("PUT")
        assert not validator.is_method_allowed("DELETE")
        assert not validator.is_method_allowed("PATCH")
        assert not validator.is_method_allowed("POST")

    def test_invalid_scheme_out_of_scope(self, validator):
        """Test that non-HTTP schemes are out of scope."""
        assert not validator.is_in_scope("ftp://example.com/file")
        assert not validator.is_in_scope("file:///etc/passwd")
        assert not validator.is_in_scope("javascript:alert(1)")

    def test_stats(self, validator):
        """Test stats retrieval."""
        stats = validator.get_stats()
        assert "urls_processed" in stats
        assert "max_urls" in stats
        assert "max_rps" in stats
        assert stats["max_urls"] == 100


class TestScopeValidatorWithSubdomains:
    """Tests for scope validation with subdomain variations."""

    def test_subdomain_excluded_by_default(self):
        """Test that subdomains are excluded by default."""
        config = {
            "scope": {"same_origin_only": True},
            "rate_limits": {},
        }
        validator = ScopeValidator(
            target="https://example.com",
            config=config,
            ignore_robots=True,
        )

        assert not validator.is_in_scope("https://api.example.com/path")
        assert not validator.is_in_scope("https://www.example.com/path")


class TestRateLimiting:
    """Tests for rate limiting functionality."""

    @pytest.fixture
    def rate_limited_validator(self):
        """Return a validator with low rate limits for testing."""
        config = {
            "scope": {"same_origin_only": True},
            "rate_limits": {
                "requests_per_second": 2,
                "max_concurrency": 1,
                "max_urls": 5,
            },
        }
        return ScopeValidator(
            target="https://example.com",
            config=config,
            ignore_robots=True,
        )

    @pytest.mark.asyncio
    async def test_acquire_rate_limit_succeeds(self, rate_limited_validator):
        """Test that rate limit acquisition succeeds initially."""
        result = await rate_limited_validator.acquire_rate_limit()
        assert result is True

    @pytest.mark.asyncio
    async def test_url_limit_enforced(self, rate_limited_validator):
        """Test that URL limit is enforced."""
        # Acquire up to the limit
        for _ in range(5):
            result = await rate_limited_validator.acquire_rate_limit()
            assert result is True

        # Next should fail
        result = await rate_limited_validator.acquire_rate_limit()
        assert result is False
