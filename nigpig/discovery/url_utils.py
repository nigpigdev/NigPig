"""URL utilities - normalization, deduplication, scope validation."""

from urllib.parse import ParseResult, parse_qs, urlencode, urlparse, urlunparse


def normalize_url(url: str) -> str:
    """Normalize a URL for consistent comparison.

    - Lowercases the scheme and host
    - Removes default ports (80, 443)
    - Removes trailing slashes from paths (except root)
    - Sorts query parameters
    - Removes fragment

    Args:
        url: URL to normalize.

    Returns:
        Normalized URL.
    """
    try:
        parsed = urlparse(url)

        # Lowercase scheme and host
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()

        # Remove default ports
        if ":" in netloc:
            host, port = netloc.rsplit(":", 1)
            if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                netloc = host

        # Normalize path
        path = parsed.path
        if path and path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        if not path:
            path = "/"

        # Sort query parameters
        query = ""
        if parsed.query:
            params = parse_qs(parsed.query, keep_blank_values=True)
            # Sort by key
            sorted_params = sorted(params.items())
            query = urlencode(sorted_params, doseq=True)

        # Rebuild URL without fragment
        normalized = ParseResult(
            scheme=scheme,
            netloc=netloc,
            path=path,
            params="",
            query=query,
            fragment="",
        )

        return urlunparse(normalized)

    except Exception:
        return url


def deduplicate_urls(urls: list[str]) -> list[str]:
    """Remove duplicate URLs after normalization.

    Args:
        urls: List of URLs.

    Returns:
        Deduplicated list of URLs.
    """
    seen: set[str] = set()
    unique: list[str] = []

    for url in urls:
        normalized = normalize_url(url)
        if normalized not in seen:
            seen.add(normalized)
            unique.append(url)

    return unique


def is_same_origin(url1: str, url2: str) -> bool:
    """Check if two URLs have the same origin.

    Same origin = same scheme + host + port.

    Args:
        url1: First URL.
        url2: Second URL.

    Returns:
        True if same origin.
    """
    try:
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)

        scheme1 = parsed1.scheme.lower()
        scheme2 = parsed2.scheme.lower()

        if scheme1 != scheme2:
            return False

        # Normalize netloc by removing default ports
        def normalize_netloc(scheme: str, netloc: str) -> str:
            netloc = netloc.lower()
            if ":" in netloc:
                host, port = netloc.rsplit(":", 1)
                if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
                    return host
            return netloc

        netloc1 = normalize_netloc(scheme1, parsed1.netloc)
        netloc2 = normalize_netloc(scheme2, parsed2.netloc)

        return netloc1 == netloc2
    except Exception:
        return False


def is_same_host(url1: str, url2: str) -> bool:
    """Check if two URLs have the same host (ignoring port).

    Args:
        url1: First URL.
        url2: Second URL.

    Returns:
        True if same host.
    """
    try:
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)

        host1 = parsed1.netloc.split(":")[0].lower()
        host2 = parsed2.netloc.split(":")[0].lower()

        return host1 == host2
    except Exception:
        return False


def get_base_url(url: str) -> str:
    """Get the base URL (scheme + host).

    Args:
        url: Full URL.

    Returns:
        Base URL.
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def extract_parameters(url: str) -> dict[str, list[str]]:
    """Extract query parameters from URL.

    Args:
        url: URL with query string.

    Returns:
        Dictionary of parameter names to values.
    """
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def classify_endpoint(url: str) -> str:
    """Classify an endpoint based on path pattern.

    Args:
        url: URL to classify.

    Returns:
        Classification string.
    """
    parsed = urlparse(url)
    path = parsed.path.lower()

    # API endpoints
    if "/api/" in path or path.startswith("/api"):
        return "api"

    # Static assets
    static_extensions = (
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
    )
    if path.endswith(static_extensions):
        return "static"

    # Form endpoints
    form_keywords = (
        "login",
        "signin",
        "signup",
        "register",
        "password",
        "reset",
        "submit",
        "contact",
    )
    if any(kw in path for kw in form_keywords):
        return "form"

    # Admin endpoints
    admin_keywords = ("admin", "dashboard", "manage", "config", "settings")
    if any(kw in path for kw in admin_keywords):
        return "admin"

    return "general"


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid HTTP/HTTPS URL.

    Args:
        url: String to validate.

    Returns:
        True if valid URL.
    """
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def remove_fragment(url: str) -> str:
    """Remove fragment/anchor from URL.

    Args:
        url: URL possibly with fragment.

    Returns:
        URL without fragment.
    """
    try:
        parsed = urlparse(url)
        return urlunparse(parsed._replace(fragment=""))
    except Exception:
        return url


def extract_path(url: str) -> str:
    """Extract just the path from a URL.

    Args:
        url: Full URL.

    Returns:
        Path component.
    """
    try:
        parsed = urlparse(url)
        return parsed.path or "/"
    except Exception:
        return "/"
