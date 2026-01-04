"""Tests for URL utilities."""

import pytest

from nigpig.discovery.url_utils import (
    normalize_url,
    deduplicate_urls,
    is_same_origin,
    is_same_host,
    is_valid_url,
    extract_path,
    classify_endpoint,
)


class TestNormalizeUrl:
    """Tests for URL normalization."""

    def test_lowercase_scheme_and_host(self):
        """Test that scheme and host are lowercased."""
        assert normalize_url("HTTP://EXAMPLE.COM/path") == "http://example.com/path"
        assert normalize_url("HTTPS://Example.Com/PATH") == "https://example.com/PATH"

    def test_remove_default_ports(self):
        """Test that default ports are removed."""
        assert normalize_url("http://example.com:80/path") == "http://example.com/path"
        assert normalize_url("https://example.com:443/path") == "https://example.com/path"

        # Non-default ports should be kept
        assert "8080" in normalize_url("http://example.com:8080/path")

    def test_remove_trailing_slash(self):
        """Test that trailing slashes are removed except for root."""
        assert normalize_url("http://example.com/path/") == "http://example.com/path"
        assert normalize_url("http://example.com/") == "http://example.com/"

    def test_sort_query_params(self):
        """Test that query parameters are sorted."""
        url1 = normalize_url("http://example.com/path?b=2&a=1")
        url2 = normalize_url("http://example.com/path?a=1&b=2")
        assert url1 == url2

    def test_remove_fragment(self):
        """Test that fragments are removed."""
        assert normalize_url("http://example.com/path#section") == "http://example.com/path"

    def test_add_root_path(self):
        """Test that empty path becomes root."""
        result = normalize_url("http://example.com")
        assert result.endswith("/")


class TestDeduplicateUrls:
    """Tests for URL deduplication."""

    def test_removes_exact_duplicates(self):
        """Test removal of exact duplicates."""
        urls = [
            "http://example.com/page1",
            "http://example.com/page2",
            "http://example.com/page1",
        ]
        result = deduplicate_urls(urls)
        assert len(result) == 2

    def test_removes_normalized_duplicates(self):
        """Test removal of duplicates after normalization."""
        urls = [
            "http://example.com/path",
            "HTTP://EXAMPLE.COM/path",
            "http://example.com/path/",
        ]
        result = deduplicate_urls(urls)
        assert len(result) == 1

    def test_preserves_different_urls(self):
        """Test that different URLs are preserved."""
        urls = [
            "http://example.com/page1",
            "http://example.com/page2",
            "http://example.com/page3",
        ]
        result = deduplicate_urls(urls)
        assert len(result) == 3


class TestIsSameOrigin:
    """Tests for same-origin check."""

    def test_same_origin(self):
        """Test matching origins."""
        assert is_same_origin("http://example.com/path1", "http://example.com/path2")
        assert is_same_origin("https://example.com:443/path", "https://example.com/other")

    def test_different_scheme(self):
        """Test different schemes."""
        assert not is_same_origin("http://example.com/path", "https://example.com/path")

    def test_different_host(self):
        """Test different hosts."""
        assert not is_same_origin("http://example.com/path", "http://other.com/path")

    def test_different_port(self):
        """Test different ports."""
        assert not is_same_origin("http://example.com:8080/path", "http://example.com:9090/path")


class TestIsSameHost:
    """Tests for same-host check."""

    def test_same_host_different_ports(self):
        """Test same host with different ports."""
        assert is_same_host("http://example.com:8080/path", "http://example.com:9090/path")

    def test_different_hosts(self):
        """Test different hosts."""
        assert not is_same_host("http://example.com/path", "http://other.com/path")


class TestIsValidUrl:
    """Tests for URL validation."""

    def test_valid_http_url(self):
        """Test valid HTTP URLs."""
        assert is_valid_url("http://example.com")
        assert is_valid_url("https://example.com/path?query=1")

    def test_invalid_urls(self):
        """Test invalid URLs."""
        assert not is_valid_url("ftp://example.com")
        assert not is_valid_url("not-a-url")
        assert not is_valid_url("")


class TestClassifyEndpoint:
    """Tests for endpoint classification."""

    def test_api_endpoints(self):
        """Test API endpoint classification."""
        assert classify_endpoint("http://example.com/api/users") == "api"
        assert classify_endpoint("http://example.com/v1/api/data") == "api"

    def test_static_assets(self):
        """Test static asset classification."""
        assert classify_endpoint("http://example.com/style.css") == "static"
        assert classify_endpoint("http://example.com/script.js") == "static"
        assert classify_endpoint("http://example.com/image.png") == "static"

    def test_form_endpoints(self):
        """Test form endpoint classification."""
        assert classify_endpoint("http://example.com/login") == "form"
        assert classify_endpoint("http://example.com/signup") == "form"

    def test_admin_endpoints(self):
        """Test admin endpoint classification."""
        assert classify_endpoint("http://example.com/admin/users") == "admin"
        assert classify_endpoint("http://example.com/dashboard") == "admin"


class TestExtractPath:
    """Tests for path extraction."""

    def test_extract_simple_path(self):
        """Test simple path extraction."""
        assert extract_path("http://example.com/path/to/page") == "/path/to/page"

    def test_extract_root_path(self):
        """Test root path extraction."""
        assert extract_path("http://example.com") == "/"
        assert extract_path("http://example.com/") == "/"
