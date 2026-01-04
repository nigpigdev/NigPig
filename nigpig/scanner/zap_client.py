"""OWASP ZAP API Client wrapper."""

import asyncio
import contextlib
import subprocess
from typing import Any

import httpx


class ZAPClientError(Exception):
    """Exception raised for ZAP client errors."""

    pass


class ZAPClient:
    """OWASP ZAP API client with auto-start capability."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8080,
        api_key: str = "",
        timeout: int = 300,
    ):
        """Initialize ZAP client.

        Args:
            host: ZAP API host.
            port: ZAP API port.
            api_key: ZAP API key (empty if disabled).
            timeout: Request timeout in seconds.
        """
        self.host = host
        self.port = port
        self.api_key = api_key
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> "ZAPClient":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(timeout=self.timeout)
        await self._ensure_running()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()

    async def _ensure_running(self, max_retries: int = 3) -> None:
        """Ensure ZAP is running, try to start if not.

        Args:
            max_retries: Maximum number of start attempts.

        Raises:
            ZAPClientError: If ZAP cannot be started.
        """
        for attempt in range(max_retries):
            if await self._is_running():
                return

            if attempt == 0:
                # Try to start via docker-compose
                await self._start_docker()
                await asyncio.sleep(10)  # Wait for ZAP to initialize
            else:
                await asyncio.sleep(5 * (attempt + 1))

        raise ZAPClientError(
            f"ZAP is not running at {self.base_url}. Please run: docker-compose up -d zap"
        )

    async def _is_running(self) -> bool:
        """Check if ZAP is running."""
        try:
            if not self._client:
                return False
            response = await self._client.get(
                f"{self.base_url}/JSON/core/view/version/",
                timeout=5,
            )
            return response.status_code == 200
        except Exception:
            return False

    async def _start_docker(self) -> None:
        """Attempt to start ZAP via docker-compose."""
        with contextlib.suppress(Exception):
            subprocess.run(
                ["docker-compose", "up", "-d", "zap"],
                capture_output=True,
                timeout=60,
            )

    async def _api_call(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Make an API call to ZAP.

        Args:
            endpoint: API endpoint path.
            params: Query parameters.

        Returns:
            JSON response dictionary.

        Raises:
            ZAPClientError: If the API call fails.
        """
        if not self._client:
            raise ZAPClientError("Client not initialized")

        url = f"{self.base_url}{endpoint}"
        params = params or {}

        if self.api_key:
            params["apikey"] = self.api_key

        try:
            response = await self._client.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise ZAPClientError(f"ZAP API error: {e.response.status_code}") from e
        except httpx.RequestError as e:
            raise ZAPClientError(f"ZAP request failed: {e}") from e

    async def get_version(self) -> str:
        """Get ZAP version."""
        result = await self._api_call("/JSON/core/view/version/")
        return result.get("version", "unknown")

    async def new_session(self, name: str = "") -> None:
        """Create a new ZAP session.

        Args:
            name: Optional session name.
        """
        params = {"overwrite": "true"}
        if name:
            params["name"] = name
        await self._api_call("/JSON/core/action/newSession/", params)

    async def access_url(self, url: str) -> None:
        """Access a URL through ZAP (seeds the spider).

        Args:
            url: URL to access.
        """
        await self._api_call("/JSON/core/action/accessUrl/", {"url": url})

    async def set_context_include(self, context: str, regex: str) -> None:
        """Set context include regex.

        Args:
            context: Context name.
            regex: Include regex pattern.
        """
        await self._api_call(
            "/JSON/context/action/includeInContext/",
            {"contextName": context, "regex": regex},
        )

    # Spider methods
    async def start_spider(
        self,
        url: str,
        max_depth: int = 5,
        max_duration: int = 10,
    ) -> str:
        """Start the spider crawler.

        Args:
            url: Target URL.
            max_depth: Maximum crawl depth.
            max_duration: Maximum duration in minutes.

        Returns:
            Scan ID.
        """
        # Set spider options
        await self._api_call(
            "/JSON/spider/action/setOptionMaxDepth/",
            {"Integer": str(max_depth)},
        )
        await self._api_call(
            "/JSON/spider/action/setOptionMaxDuration/",
            {"Integer": str(max_duration)},
        )

        result = await self._api_call("/JSON/spider/action/scan/", {"url": url})
        return result.get("scan", "0")

    async def get_spider_status(self, scan_id: str) -> int:
        """Get spider progress percentage.

        Args:
            scan_id: Spider scan ID.

        Returns:
            Progress percentage (0-100).
        """
        result = await self._api_call(
            "/JSON/spider/view/status/",
            {"scanId": scan_id},
        )
        return int(result.get("status", "0"))

    async def wait_for_spider(
        self,
        scan_id: str,
        poll_interval: float = 2.0,
    ) -> None:
        """Wait for spider to complete.

        Args:
            scan_id: Spider scan ID.
            poll_interval: Polling interval in seconds.
        """
        while await self.get_spider_status(scan_id) < 100:
            await asyncio.sleep(poll_interval)

    async def get_spider_results(self, scan_id: str) -> list[str]:
        """Get URLs found by spider.

        Args:
            scan_id: Spider scan ID.

        Returns:
            List of discovered URLs.
        """
        result = await self._api_call(
            "/JSON/spider/view/results/",
            {"scanId": scan_id},
        )
        return result.get("results", [])

    # AJAX Spider methods
    async def start_ajax_spider(self, url: str, max_duration: int = 5) -> None:
        """Start the AJAX spider.

        Args:
            url: Target URL.
            max_duration: Maximum duration in minutes.
        """
        await self._api_call(
            "/JSON/ajaxSpider/action/setOptionMaxDuration/",
            {"Integer": str(max_duration)},
        )
        await self._api_call("/JSON/ajaxSpider/action/scan/", {"url": url})

    async def get_ajax_spider_status(self) -> str:
        """Get AJAX spider status.

        Returns:
            Status string (running, stopped).
        """
        result = await self._api_call("/JSON/ajaxSpider/view/status/")
        return result.get("status", "stopped")

    async def wait_for_ajax_spider(self, poll_interval: float = 2.0) -> None:
        """Wait for AJAX spider to complete."""
        while await self.get_ajax_spider_status() == "running":
            await asyncio.sleep(poll_interval)

    # Passive scan methods
    async def get_passive_scan_records_left(self) -> int:
        """Get number of records waiting to be passively scanned.

        Returns:
            Number of records left.
        """
        result = await self._api_call("/JSON/pscan/view/recordsToScan/")
        return int(result.get("recordsToScan", "0"))

    async def wait_for_passive_scan(self, poll_interval: float = 1.0) -> None:
        """Wait for passive scan to complete."""
        while await self.get_passive_scan_records_left() > 0:
            await asyncio.sleep(poll_interval)

    # Active scan methods
    async def start_active_scan(
        self,
        url: str,
        policy: str = "Light",
        recurse: bool = True,
    ) -> str:
        """Start active scan.

        Args:
            url: Target URL.
            policy: Scan policy name.
            recurse: Whether to scan recursively.

        Returns:
            Scan ID.
        """
        result = await self._api_call(
            "/JSON/ascan/action/scan/",
            {
                "url": url,
                "recurse": str(recurse).lower(),
                "scanPolicyName": policy,
            },
        )
        return result.get("scan", "0")

    async def get_active_scan_status(self, scan_id: str) -> int:
        """Get active scan progress percentage.

        Args:
            scan_id: Active scan ID.

        Returns:
            Progress percentage (0-100).
        """
        result = await self._api_call(
            "/JSON/ascan/view/status/",
            {"scanId": scan_id},
        )
        return int(result.get("status", "0"))

    async def wait_for_active_scan(
        self,
        scan_id: str,
        poll_interval: float = 5.0,
    ) -> None:
        """Wait for active scan to complete.

        Args:
            scan_id: Active scan ID.
            poll_interval: Polling interval in seconds.
        """
        while await self.get_active_scan_status(scan_id) < 100:
            await asyncio.sleep(poll_interval)

    async def stop_active_scan(self, scan_id: str) -> None:
        """Stop an active scan.

        Args:
            scan_id: Active scan ID.
        """
        await self._api_call(
            "/JSON/ascan/action/stop/",
            {"scanId": scan_id},
        )

    # Alert methods
    async def get_alerts(
        self,
        base_url: str = "",
        start: int = 0,
        count: int = 1000,
    ) -> list[dict[str, Any]]:
        """Get alerts/findings.

        Args:
            base_url: Filter by base URL.
            start: Starting index.
            count: Maximum number to return.

        Returns:
            List of alert dictionaries.
        """
        params = {"start": str(start), "count": str(count)}
        if base_url:
            params["baseurl"] = base_url

        result = await self._api_call("/JSON/core/view/alerts/", params)
        return result.get("alerts", [])

    async def get_alerts_summary(self, base_url: str = "") -> dict[str, int]:
        """Get alerts summary by risk level.

        Args:
            base_url: Filter by base URL.

        Returns:
            Dictionary mapping risk levels to counts.
        """
        params = {}
        if base_url:
            params["baseurl"] = base_url

        result = await self._api_call("/JSON/core/view/alertsSummary/", params)
        return result.get("alertsSummary", {})

    # Message/Request inspection
    async def get_messages(
        self,
        base_url: str,
        start: int = 0,
        count: int = 100,
    ) -> list[dict[str, Any]]:
        """Get HTTP messages (requests/responses).

        Args:
            base_url: Filter by base URL.
            start: Starting index.
            count: Maximum number to return.

        Returns:
            List of message dictionaries.
        """
        result = await self._api_call(
            "/JSON/core/view/messages/",
            {"baseurl": base_url, "start": str(start), "count": str(count)},
        )
        return result.get("messages", [])
