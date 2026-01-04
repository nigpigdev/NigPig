"""JavaScript analysis - endpoint and secret extraction from JS files."""

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx


@dataclass
class JSEndpoint:
    """Endpoint discovered in JavaScript."""

    url: str
    source_file: str
    method: str = "GET"
    context: str = ""


@dataclass
class JSSecret:
    """Potential secret found in JavaScript."""

    type: str
    value: str
    source_file: str
    line: int = 0
    context: str = ""


class JSAnalyzer:
    """Analyze JavaScript files for endpoints and secrets."""

    # Patterns to extract endpoints
    ENDPOINT_PATTERNS = [
        # API paths
        r'["\']/(api|v\d+)/[a-zA-Z0-9/_-]+["\']',
        r'["\']/[a-zA-Z0-9/_-]+\.(json|xml|php|asp|jsp)["\']',
        # Full URLs
        r"https?://[a-zA-Z0-9.-]+[a-zA-Z0-9./?=&_-]*",
        # Fetch/XHR patterns
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
        r'axios\s*[.(]\s*["\']([^"\']+)["\']',
        # URL builders
        r'url\s*[=:]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[=:]\s*["\']([^"\']+)["\']',
        r'baseURL\s*[=:]\s*["\']([^"\']+)["\']',
        r'apiUrl\s*[=:]\s*["\']([^"\']+)["\']',
    ]

    # Secret patterns (regex pattern, type name)
    SECRET_PATTERNS = [
        # AWS
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
        (
            r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[=:]\s*["\']([^"\']+)["\']',
            "AWS Secret Key",
        ),
        # Google
        (r"AIza[0-9A-Za-z_-]{35}", "Google API Key"),
        (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth"),
        # GitHub
        (r"ghp_[0-9A-Za-z]{36}", "GitHub Personal Token"),
        (r"gho_[0-9A-Za-z]{36}", "GitHub OAuth Token"),
        (r"ghu_[0-9A-Za-z]{36}", "GitHub User Token"),
        # Stripe
        (r"sk_live_[0-9a-zA-Z]{24}", "Stripe Secret Key"),
        (r"pk_live_[0-9a-zA-Z]{24}", "Stripe Publishable Key"),
        # Slack
        (r"xox[baprs]-[0-9A-Za-z-]+", "Slack Token"),
        # Twilio
        (r"SK[0-9a-fA-F]{32}", "Twilio API Key"),
        # Generic secrets
        (r'["\']?api[_-]?key["\']?\s*[=:]\s*["\']([^"\']{8,})["\']', "API Key"),
        (r'["\']?secret[_-]?key["\']?\s*[=:]\s*["\']([^"\']{8,})["\']', "Secret Key"),
        (r'["\']?access[_-]?token["\']?\s*[=:]\s*["\']([^"\']{8,})["\']', "Access Token"),
        (r'["\']?auth[_-]?token["\']?\s*[=:]\s*["\']([^"\']{8,})["\']', "Auth Token"),
        (r'["\']?private[_-]?key["\']?\s*[=:]\s*["\']([^"\']{8,})["\']', "Private Key"),
        # JWT
        (r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", "JWT Token"),
        # Passwords in config
        (r'["\']?password["\']?\s*[=:]\s*["\']([^"\']+)["\']', "Password"),
        # S3 buckets
        (r"[a-zA-Z0-9.-]+\.s3\.amazonaws\.com", "S3 Bucket"),
        (r"s3://[a-zA-Z0-9.-]+", "S3 Bucket"),
        # Firebase
        (r"[a-zA-Z0-9-]+\.firebaseio\.com", "Firebase URL"),
        (r"[a-zA-Z0-9-]+\.firebaseapp\.com", "Firebase App"),
    ]

    def __init__(self, base_url: str, timeout: float = 15.0):
        """Initialize JS analyzer.

        Args:
            base_url: Base URL for relative path resolution.
            timeout: Request timeout.
        """
        self.base_url = base_url
        self.timeout = timeout

    async def analyze_url(self, js_url: str) -> tuple[list[JSEndpoint], list[JSSecret]]:
        """Analyze a JavaScript file from URL.

        Args:
            js_url: URL to JavaScript file.

        Returns:
            Tuple of (endpoints, secrets).
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(js_url)
                if response.status_code == 200:
                    return self.analyze_content(response.text, js_url)
        except Exception:
            pass

        return [], []

    def analyze_content(
        self,
        content: str,
        source_file: str = "inline",
    ) -> tuple[list[JSEndpoint], list[JSSecret]]:
        """Analyze JavaScript content.

        Args:
            content: JavaScript source code.
            source_file: Source file identifier.

        Returns:
            Tuple of (endpoints, secrets).
        """
        endpoints = self._extract_endpoints(content, source_file)
        secrets = self._extract_secrets(content, source_file)

        return endpoints, secrets

    def _extract_endpoints(
        self,
        content: str,
        source_file: str,
    ) -> list[JSEndpoint]:
        """Extract API endpoints from JS content.

        Args:
            content: JavaScript source.
            source_file: Source file identifier.

        Returns:
            List of discovered endpoints.
        """
        endpoints: list[JSEndpoint] = []
        seen: set[str] = set()

        for pattern in self.ENDPOINT_PATTERNS:
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Get the full match or first group
                    url = match.group(1) if match.groups() else match.group(0)
                    url = url.strip("\"'")

                    if not url or url in seen:
                        continue

                    # Skip common false positives
                    if self._is_false_positive(url):
                        continue

                    seen.add(url)

                    # Determine method from context
                    method = self._guess_method(content, match.start())

                    # Resolve relative URLs
                    if url.startswith("/"):
                        url = urljoin(self.base_url, url)

                    # Get context
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace("\n", " ").strip()

                    endpoints.append(
                        JSEndpoint(
                            url=url,
                            source_file=source_file,
                            method=method,
                            context=context[:100],
                        )
                    )
            except Exception:
                continue

        return endpoints

    def _extract_secrets(
        self,
        content: str,
        source_file: str,
    ) -> list[JSSecret]:
        """Extract potential secrets from JS content.

        Args:
            content: JavaScript source.
            source_file: Source file identifier.

        Returns:
            List of potential secrets.
        """
        secrets: list[JSSecret] = []
        seen: set[str] = set()

        lines = content.split("\n")

        for pattern, secret_type in self.SECRET_PATTERNS:
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Get the value
                    value = match.group(1) if match.groups() else match.group(0)

                    if not value or value in seen:
                        continue

                    # Skip too short values
                    if len(value) < 8:
                        continue

                    seen.add(value)

                    # Find line number
                    line_num = content[: match.start()].count("\n") + 1

                    # Get context
                    start = max(0, match.start() - 30)
                    end = min(len(content), match.end() + 30)
                    context = content[start:end].replace("\n", " ").strip()

                    secrets.append(
                        JSSecret(
                            type=secret_type,
                            value=value[:50] + "..." if len(value) > 50 else value,
                            source_file=source_file,
                            line=line_num,
                            context=context[:80],
                        )
                    )
            except Exception:
                continue

        return secrets

    def _is_false_positive(self, url: str) -> bool:
        """Check if URL is likely a false positive.

        Args:
            url: URL to check.

        Returns:
            True if likely false positive.
        """
        false_positives = [
            "example.com",
            "localhost",
            "127.0.0.1",
            "schema.org",
            "w3.org",
            "mozilla.org",
            ".svg",
            ".png",
            ".jpg",
            ".gif",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".css",
            ".scss",
            ".less",
        ]

        url_lower = url.lower()
        return any(fp in url_lower for fp in false_positives)

    def _guess_method(self, content: str, position: int) -> str:
        """Guess HTTP method from surrounding context.

        Args:
            content: Full content.
            position: Match position.

        Returns:
            HTTP method.
        """
        # Look back for method hints
        start = max(0, position - 50)
        context = content[start:position].lower()

        if ".post(" in context or "method: 'post'" in context or '"post"' in context:
            return "POST"
        if ".put(" in context or "method: 'put'" in context:
            return "PUT"
        if ".delete(" in context or "method: 'delete'" in context:
            return "DELETE"
        if ".patch(" in context or "method: 'patch'" in context:
            return "PATCH"

        return "GET"


async def find_js_files(base_url: str, timeout: float = 15.0) -> list[str]:
    """Find JavaScript files from a page.

    Args:
        base_url: Page URL to analyze.
        timeout: Request timeout.

    Returns:
        List of JavaScript file URLs.
    """
    from bs4 import BeautifulSoup

    js_files: list[str] = []

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(base_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")

                for script in soup.find_all("script", src=True):
                    src = script["src"]
                    if src:
                        full_url = urljoin(base_url, src)
                        if full_url not in js_files:
                            js_files.append(full_url)
    except Exception:
        pass

    return js_files
