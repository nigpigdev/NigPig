"""Scope validation and rate limiting."""

import asyncio
import time
from typing import Any, Optional
from urllib.parse import urlparse

from nigpig.discovery.robots import parse_robots_txt, is_path_allowed, RobotsRules
from nigpig.discovery.url_utils import is_same_origin, is_same_host, extract_path


class ScopeValidator:
    """Validates URLs against scope and enforces rate limits."""

    def __init__(
        self,
        target: str,
        config: dict[str, Any],
        ignore_robots: bool = False,
    ):
        """Initialize scope validator.

        Args:
            target: Target base URL.
            config: Configuration dictionary.
            ignore_robots: Whether to ignore robots.txt.
        """
        self.target = target
        self.config = config
        self.ignore_robots = ignore_robots

        # Parse target for origin checking
        parsed = urlparse(target)
        self.target_scheme = parsed.scheme.lower()
        self.target_host = parsed.netloc.lower().split(":")[0]
        self.target_netloc = parsed.netloc.lower()

        # Scope config
        scope_config = config.get("scope", {})
        self.same_origin_only = scope_config.get("same_origin_only", True)
        self.respect_robots = scope_config.get("respect_robots_txt", True) and not ignore_robots
        self.allowed_methods = set(
            m.upper() for m in scope_config.get("allowed_methods", ["GET", "HEAD", "OPTIONS"])
        )
        self.blocked_methods = set(
            m.upper()
            for m in scope_config.get("blocked_methods", ["PUT", "DELETE", "PATCH", "POST"])
        )

        # Rate limiting
        rate_config = config.get("rate_limits", {})
        self.max_rps = rate_config.get("requests_per_second", 10)
        self.max_concurrency = rate_config.get("max_concurrency", 5)
        self.max_urls = rate_config.get("max_urls", 500)

        # State
        self._robots_rules: Optional[RobotsRules] = None
        self._robots_checked = False
        self._request_times: list[float] = []
        self._request_lock = asyncio.Lock()
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self._url_count = 0

    async def init_robots(self) -> None:
        """Initialize robots.txt rules."""
        if not self.respect_robots or self._robots_checked:
            return

        self._robots_rules = await parse_robots_txt(self.target)
        self._robots_checked = True

    def is_in_scope(self, url: str) -> bool:
        """Check if a URL is in scope.

        Args:
            url: URL to check.

        Returns:
            True if URL is in scope.
        """
        try:
            parsed = urlparse(url)

            # Check scheme
            if parsed.scheme.lower() not in ("http", "https"):
                return False

            # Check origin/host
            if self.same_origin_only:
                url_host = parsed.netloc.lower().split(":")[0]
                if url_host != self.target_host:
                    return False

            # Check robots.txt if loaded
            if self._robots_rules and self.respect_robots:
                path = extract_path(url)
                if not is_path_allowed(path, self._robots_rules):
                    return False

            return True

        except Exception:
            return False

    def is_method_allowed(self, method: str) -> bool:
        """Check if an HTTP method is allowed.

        Args:
            method: HTTP method.

        Returns:
            True if method is allowed.
        """
        method_upper = method.upper()

        # Explicitly blocked methods
        if method_upper in self.blocked_methods:
            return False

        # Must be in allowed list
        return method_upper in self.allowed_methods

    async def acquire_rate_limit(self) -> bool:
        """Wait for rate limit slot.

        Returns:
            True if slot acquired, False if max URLs reached.
        """
        async with self._request_lock:
            # Check URL count limit
            if self._url_count >= self.max_urls:
                return False

            # Rate limiting
            now = time.time()

            # Clean old timestamps (older than 1 second)
            self._request_times = [t for t in self._request_times if now - t < 1.0]

            # Wait if at limit
            while len(self._request_times) >= self.max_rps:
                await asyncio.sleep(0.1)
                now = time.time()
                self._request_times = [t for t in self._request_times if now - t < 1.0]

            self._request_times.append(now)
            self._url_count += 1
            return True

    async def acquire_concurrency(self) -> asyncio.Semaphore:
        """Get concurrency semaphore for use as context manager.

        Returns:
            Semaphore for concurrency control.
        """
        return self._semaphore

    def get_crawl_delay(self) -> Optional[float]:
        """Get robots.txt crawl-delay if specified.

        Returns:
            Crawl delay in seconds or None.
        """
        if self._robots_rules and self._robots_rules.crawl_delay:
            return self._robots_rules.crawl_delay
        return None

    def get_stats(self) -> dict[str, Any]:
        """Get current stats.

        Returns:
            Stats dictionary.
        """
        return {
            "urls_processed": self._url_count,
            "max_urls": self.max_urls,
            "max_rps": self.max_rps,
            "max_concurrency": self.max_concurrency,
            "robots_loaded": self._robots_rules is not None,
        }
