"""Content fuzzing - directory/file discovery with wordlists."""

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator
from urllib.parse import urljoin

import httpx


@dataclass
class FuzzResult:
    """Result of fuzzing attempt."""

    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    redirect_url: str = ""


# Common extensions to try
COMMON_EXTENSIONS = [
    "",
    ".php",
    ".html",
    ".js",
    ".json",
    ".xml",
    ".asp",
    ".aspx",
    ".jsp",
    ".txt",
    ".bak",
    ".old",
    ".zip",
    ".tar.gz",
    ".sql",
    ".log",
    ".env",
    ".config",
    ".yml",
    ".yaml",
    ".ini",
    ".conf",
]

# Default wordlist (built-in mini version)
DEFAULT_WORDLIST = [
    "admin",
    "login",
    "dashboard",
    "api",
    "config",
    "backup",
    "test",
    "dev",
    "staging",
    "beta",
    "debug",
    "status",
    "health",
    "info",
    "version",
    "docs",
    "documentation",
    "help",
    "support",
    "faq",
    "about",
    "contact",
    "privacy",
    "terms",
    "robots.txt",
    "sitemap.xml",
    ".git",
    ".env",
    ".htaccess",
    "wp-admin",
    "wp-login.php",
    "wp-content",
    "phpmyadmin",
    "adminer",
    "phpinfo.php",
    "server-status",
    "elmah.axd",
    "console",
    "manager",
    "shell",
    "cmd",
    "exec",
    "system",
    "upload",
    "uploads",
    "files",
    "images",
    "static",
    "assets",
    "media",
    "css",
    "js",
    "fonts",
    "vendor",
    "node_modules",
    "bower_components",
    "cgi-bin",
    "scripts",
    "includes",
    "inc",
    "lib",
    "classes",
    "src",
    "tmp",
    "temp",
    "cache",
    "logs",
    "log",
    "error_log",
    "debug.log",
    "database",
    "db",
    "sql",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "graphql",
    "rest",
    "soap",
    "wsdl",
    "swagger",
    "openapi",
    "v1",
    "v2",
    "v3",
    "api/v1",
    "api/v2",
    "api/v3",
    ".well-known",
    "security.txt",
    "humans.txt",
    "crossdomain.xml",
]


class ContentFuzzer:
    """Directory and file content discovery via fuzzing."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 10.0,
        max_concurrent: int = 20,
        rate_limit: float = 20.0,
        follow_redirects: bool = False,
    ):
        """Initialize content fuzzer.

        Args:
            base_url: Base URL to fuzz.
            timeout: Request timeout.
            max_concurrent: Maximum concurrent requests.
            rate_limit: Requests per second limit.
            follow_redirects: Whether to follow redirects.
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self.follow_redirects = follow_redirects
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._delay = 1.0 / rate_limit

    async def fuzz_default(
        self,
        extensions: list[str] | None = None,
        filter_codes: list[int] | None = None,
    ) -> list[FuzzResult]:
        """Fuzz with built-in default wordlist.

        Args:
            extensions: File extensions to append.
            filter_codes: Status codes to include (default: 200, 301, 302, 403).

        Returns:
            List of discovered resources.
        """
        return await self.fuzz_list(
            DEFAULT_WORDLIST,
            extensions or [""],
            filter_codes,
        )

    async def fuzz_list(
        self,
        words: list[str],
        extensions: list[str] | None = None,
        filter_codes: list[int] | None = None,
    ) -> list[FuzzResult]:
        """Fuzz with a word list.

        Args:
            words: List of paths to try.
            extensions: Extensions to append.
            filter_codes: Status codes to include.

        Returns:
            List of discovered resources.
        """
        if filter_codes is None:
            filter_codes = [200, 201, 301, 302, 307, 308, 401, 403]

        extensions = extensions or [""]
        results: list[FuzzResult] = []

        # Generate all URLs
        urls_to_check = []
        for word in words:
            for ext in extensions:
                path = word + ext if not word.endswith(ext) else word
                url = urljoin(self.base_url + "/", path.lstrip("/"))
                urls_to_check.append(url)

        # Check in batches
        async def check_url(url: str) -> FuzzResult | None:
            async with self._semaphore:
                await asyncio.sleep(self._delay)
                return await self._check_single(url)

        tasks = [check_url(url) for url in urls_to_check]
        all_results = await asyncio.gather(*tasks)

        for result in all_results:
            if result and result.status_code in filter_codes:
                results.append(result)

        return results

    async def fuzz_wordlist_file(
        self,
        wordlist_path: str,
        extensions: list[str] | None = None,
        filter_codes: list[int] | None = None,
        max_entries: int = 50000,
    ) -> AsyncIterator[FuzzResult]:
        """Fuzz using a wordlist file.

        Args:
            wordlist_path: Path to wordlist file.
            extensions: Extensions to append.
            filter_codes: Status codes to include.
            max_entries: Maximum entries to process.

        Yields:
            FuzzResult for each discovered resource.
        """
        import aiofiles

        if filter_codes is None:
            filter_codes = [200, 201, 301, 302, 307, 308, 401, 403]

        extensions = extensions or [""]

        try:
            async with aiofiles.open(wordlist_path, "r", errors="ignore") as f:
                count = 0
                batch = []

                async for line in f:
                    if count >= max_entries:
                        break

                    word = line.strip()
                    if not word or word.startswith("#"):
                        continue

                    for ext in extensions:
                        path = word + ext if not word.endswith(ext) else word
                        url = urljoin(self.base_url + "/", path.lstrip("/"))
                        batch.append(url)

                    count += 1

                    # Process in batches
                    if len(batch) >= self.max_concurrent:
                        async for result in self._process_batch(batch, filter_codes):
                            yield result
                        batch = []

                # Process remaining
                if batch:
                    async for result in self._process_batch(batch, filter_codes):
                        yield result

        except FileNotFoundError:
            pass

    async def _process_batch(
        self,
        urls: list[str],
        filter_codes: list[int],
    ) -> AsyncIterator[FuzzResult]:
        """Process a batch of URLs.

        Args:
            urls: URLs to check.
            filter_codes: Status codes to include.

        Yields:
            FuzzResult for matching URLs.
        """

        async def check_url(url: str) -> FuzzResult | None:
            async with self._semaphore:
                await asyncio.sleep(self._delay)
                return await self._check_single(url)

        tasks = [check_url(url) for url in urls]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result and result.status_code in filter_codes:
                yield result

    async def _check_single(self, url: str) -> FuzzResult | None:
        """Check a single URL.

        Args:
            url: URL to check.

        Returns:
            FuzzResult or None on error.
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
            ) as client:
                response = await client.head(url)

                # If HEAD fails, try GET
                if response.status_code == 405:
                    response = await client.get(url)

                redirect_url = ""
                if response.status_code in [301, 302, 307, 308]:
                    redirect_url = response.headers.get("location", "")

                return FuzzResult(
                    url=url,
                    status_code=response.status_code,
                    content_length=int(response.headers.get("content-length", 0)),
                    content_type=response.headers.get("content-type", ""),
                    redirect_url=redirect_url,
                )

        except Exception:
            return None

    async def recursive_fuzz(
        self,
        max_depth: int = 2,
        filter_codes: list[int] | None = None,
    ) -> list[FuzzResult]:
        """Recursively fuzz discovered directories.

        Args:
            max_depth: Maximum recursion depth.
            filter_codes: Status codes to include.

        Returns:
            All discovered resources.
        """
        all_results: list[FuzzResult] = []
        to_explore = [self.base_url]
        explored: set[str] = set()
        depth = 0

        while to_explore and depth < max_depth:
            current_batch = to_explore[:]
            to_explore = []

            for base in current_batch:
                if base in explored:
                    continue
                explored.add(base)

                # Create fuzzer for this base
                fuzzer = ContentFuzzer(
                    base,
                    timeout=self.timeout,
                    max_concurrent=self.max_concurrent,
                    rate_limit=self.rate_limit,
                )

                results = await fuzzer.fuzz_default(filter_codes=filter_codes)
                all_results.extend(results)

                # Find directories to explore
                for r in results:
                    if r.status_code in [200, 301, 302] and not Path(r.url).suffix:
                        # Likely a directory
                        to_explore.append(r.url.rstrip("/"))

            depth += 1

        return all_results
