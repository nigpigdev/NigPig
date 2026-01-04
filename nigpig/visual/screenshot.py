"""Screenshot capture using Playwright."""

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

try:
    from playwright.async_api import async_playwright, Browser, Page

    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


@dataclass
class ScreenshotResult:
    """Result of screenshot capture."""

    url: str
    file_path: str
    title: str = ""
    status_code: int = 0
    width: int = 1920
    height: int = 1080
    error: str = ""


class ScreenshotTaker:
    """Capture screenshots of web pages using Playwright."""

    def __init__(
        self,
        output_dir: Path | str = "screenshots",
        width: int = 1920,
        height: int = 1080,
        timeout: int = 30000,
        max_concurrent: int = 5,
    ):
        """Initialize screenshot taker.

        Args:
            output_dir: Directory to save screenshots.
            width: Viewport width.
            height: Viewport height.
            timeout: Page load timeout in milliseconds.
            max_concurrent: Maximum concurrent captures.
        """
        if not HAS_PLAYWRIGHT:
            raise ImportError(
                "Playwright not installed. Run: pip install playwright && playwright install chromium"
            )

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.width = width
        self.height = height
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._browser: Optional[Browser] = None

    async def __aenter__(self) -> "ScreenshotTaker":
        """Async context manager entry."""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._browser:
            await self._browser.close()
        if hasattr(self, "_playwright"):
            await self._playwright.stop()

    async def capture(
        self,
        url: str,
        filename: str | None = None,
        full_page: bool = False,
    ) -> ScreenshotResult:
        """Capture screenshot of a URL.

        Args:
            url: URL to capture.
            filename: Output filename (auto-generated if None).
            full_page: Whether to capture full page scroll.

        Returns:
            ScreenshotResult with file path and metadata.
        """
        if not self._browser:
            raise RuntimeError("Browser not initialized. Use 'async with' context.")

        async with self._semaphore:
            # Generate filename if not provided
            if not filename:
                from urllib.parse import urlparse
                import hashlib

                parsed = urlparse(url)
                domain = parsed.netloc.replace(":", "_")
                path_hash = hashlib.md5(parsed.path.encode()).hexdigest()[:8]
                filename = f"{domain}_{path_hash}.png"

            file_path = self.output_dir / filename

            try:
                context = await self._browser.new_context(
                    viewport={"width": self.width, "height": self.height},
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                )
                page = await context.new_page()

                response = await page.goto(url, wait_until="networkidle", timeout=self.timeout)
                status_code = response.status if response else 0

                title = await page.title()

                await page.screenshot(
                    path=str(file_path),
                    full_page=full_page,
                )

                await context.close()

                return ScreenshotResult(
                    url=url,
                    file_path=str(file_path),
                    title=title,
                    status_code=status_code,
                    width=self.width,
                    height=self.height,
                )

            except Exception as e:
                return ScreenshotResult(
                    url=url,
                    file_path="",
                    error=str(e),
                )

    async def capture_many(
        self,
        urls: list[str],
        full_page: bool = False,
    ) -> list[ScreenshotResult]:
        """Capture screenshots of multiple URLs.

        Args:
            urls: List of URLs.
            full_page: Whether to capture full page.

        Returns:
            List of results.
        """
        tasks = [self.capture(url, full_page=full_page) for url in urls]
        return await asyncio.gather(*tasks)

    async def capture_responsive(
        self,
        url: str,
        viewports: list[tuple[int, int]] | None = None,
    ) -> list[ScreenshotResult]:
        """Capture screenshots at multiple viewport sizes.

        Args:
            url: URL to capture.
            viewports: List of (width, height) tuples.

        Returns:
            List of results for each viewport.
        """
        if viewports is None:
            viewports = [
                (1920, 1080),  # Desktop
                (1366, 768),  # Laptop
                (768, 1024),  # Tablet
                (375, 812),  # Mobile
            ]

        if not self._browser:
            raise RuntimeError("Browser not initialized. Use 'async with' context.")

        results = []
        from urllib.parse import urlparse
        import hashlib

        parsed = urlparse(url)
        domain = parsed.netloc.replace(":", "_")
        path_hash = hashlib.md5(parsed.path.encode()).hexdigest()[:8]

        for width, height in viewports:
            filename = f"{domain}_{path_hash}_{width}x{height}.png"

            # Temporarily change viewport
            original_width = self.width
            original_height = self.height
            self.width = width
            self.height = height

            result = await self.capture(url, filename)
            results.append(result)

            self.width = original_width
            self.height = original_height

        return results


async def quick_screenshot(url: str, output_path: str = "screenshot.png") -> ScreenshotResult:
    """Quick screenshot capture.

    Args:
        url: URL to capture.
        output_path: Output file path.

    Returns:
        ScreenshotResult.
    """
    output_dir = Path(output_path).parent
    filename = Path(output_path).name

    async with ScreenshotTaker(output_dir=output_dir) as taker:
        return await taker.capture(url, filename)
