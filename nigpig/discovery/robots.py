"""Robots.txt parsing."""

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

import httpx


@dataclass
class RobotsRules:
    """Parsed robots.txt rules."""

    allowed: list[str]
    disallowed: list[str]
    sitemaps: list[str]
    crawl_delay: Optional[float]
    raw_content: str


def parse_robots_content(content: str) -> RobotsRules:
    """Parse robots.txt content.

    Args:
        content: Raw robots.txt content.

    Returns:
        Parsed rules.
    """
    allowed: list[str] = []
    disallowed: list[str] = []
    sitemaps: list[str] = []
    crawl_delay: Optional[float] = None

    current_agent_applies = False

    for line in content.split("\n"):
        line = line.strip()

        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        # Split directive and value
        if ":" not in line:
            continue

        directive, value = line.split(":", 1)
        directive = directive.strip().lower()
        value = value.strip()

        if directive == "user-agent":
            # Check if this section applies to us
            current_agent_applies = value == "*" or "nigpig" in value.lower()

        elif directive == "sitemap":
            # Sitemaps apply globally
            if value:
                sitemaps.append(value)

        elif current_agent_applies:
            if directive == "allow":
                if value:
                    allowed.append(value)
            elif directive == "disallow":
                if value:
                    disallowed.append(value)
            elif directive == "crawl-delay":
                try:
                    crawl_delay = float(value)
                except ValueError:
                    pass

    return RobotsRules(
        allowed=allowed,
        disallowed=disallowed,
        sitemaps=sitemaps,
        crawl_delay=crawl_delay,
        raw_content=content,
    )


async def parse_robots_txt(
    base_url: str,
    timeout: int = 10,
) -> Optional[RobotsRules]:
    """Fetch and parse robots.txt.

    Args:
        base_url: Base URL of the target.
        timeout: Request timeout.

    Returns:
        Parsed rules or None if not found.
    """
    robots_url = urljoin(base_url, "/robots.txt")

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            response = await client.get(robots_url)

            if response.status_code == 200:
                return parse_robots_content(response.text)
    except Exception:
        pass

    return None


def is_path_allowed(path: str, rules: RobotsRules) -> bool:
    """Check if a path is allowed by robots.txt rules.

    Uses simple prefix matching (not full RFC compliance).

    Args:
        path: URL path to check.
        rules: Parsed robots rules.

    Returns:
        True if path is allowed.
    """
    # Check disallow rules first
    for pattern in rules.disallowed:
        if _path_matches(path, pattern):
            # Check if there's an overriding allow rule
            for allow_pattern in rules.allowed:
                if _path_matches(path, allow_pattern):
                    # Allow rule is more specific if it's longer
                    if len(allow_pattern) >= len(pattern):
                        return True
            return False

    return True


def _path_matches(path: str, pattern: str) -> bool:
    """Check if a path matches a robots.txt pattern.

    Supports basic wildcards (*) and end-of-string ($).

    Args:
        path: URL path.
        pattern: Robots.txt pattern.

    Returns:
        True if matches.
    """
    if not pattern:
        return False

    # Handle end-of-string anchor
    if pattern.endswith("$"):
        pattern = pattern[:-1]
        return path == pattern

    # Handle wildcards
    if "*" in pattern:
        import re

        regex_pattern = pattern.replace("*", ".*")
        return bool(re.match(regex_pattern, path))

    # Simple prefix match
    return path.startswith(pattern)
