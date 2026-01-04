"""Sitemap parsing and URL extraction."""

import asyncio
import xml.etree.ElementTree as ET
from typing import Optional
from urllib.parse import urljoin

import httpx


async def fetch_sitemap_urls(
    base_url: str,
    timeout: int = 10,
    max_urls: int = 500,
) -> list[str]:
    """Fetch and parse sitemap.xml to extract URLs.

    Handles both regular sitemaps and sitemap index files.

    Args:
        base_url: Base URL of the target.
        timeout: Request timeout in seconds.
        max_urls: Maximum number of URLs to return.

    Returns:
        List of discovered URLs.
    """
    urls: list[str] = []
    sitemap_url = urljoin(base_url, "/sitemap.xml")

    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            urls = await _parse_sitemap(client, sitemap_url, max_urls)
    except Exception:
        pass  # Sitemap may not exist

    return urls[:max_urls]


async def _parse_sitemap(
    client: httpx.AsyncClient,
    sitemap_url: str,
    max_urls: int,
) -> list[str]:
    """Parse a sitemap or sitemap index.

    Args:
        client: HTTP client.
        sitemap_url: URL of the sitemap.
        max_urls: Maximum URLs to return.

    Returns:
        List of URLs.
    """
    urls: list[str] = []

    try:
        response = await client.get(sitemap_url)
        if response.status_code != 200:
            return urls

        content = response.text

        # Parse XML
        root = ET.fromstring(content)

        # Handle namespaces
        ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}

        # Check if it's a sitemap index
        sitemap_locs = root.findall(".//sm:sitemap/sm:loc", ns)
        if sitemap_locs:
            # It's a sitemap index, fetch each referenced sitemap
            tasks = []
            for loc in sitemap_locs[:10]:  # Limit to 10 sub-sitemaps
                if loc.text:
                    tasks.append(_parse_sitemap(client, loc.text, max_urls // 10))

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    urls.extend(result)
                    if len(urls) >= max_urls:
                        break
        else:
            # Regular sitemap, extract URLs
            url_locs = root.findall(".//sm:url/sm:loc", ns)
            if not url_locs:
                # Try without namespace
                url_locs = root.findall(".//url/loc")

            for loc in url_locs:
                if loc.text and len(urls) < max_urls:
                    urls.append(loc.text.strip())

    except ET.ParseError:
        pass  # Invalid XML
    except Exception:
        pass

    return urls


async def fetch_sitemap_with_alternatives(
    base_url: str,
    timeout: int = 10,
) -> list[str]:
    """Try multiple common sitemap locations.

    Args:
        base_url: Base URL of the target.
        timeout: Request timeout.

    Returns:
        List of discovered URLs.
    """
    sitemap_paths = [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemap/sitemap.xml",
        "/sitemaps/sitemap.xml",
    ]

    all_urls: list[str] = []

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for path in sitemap_paths:
            sitemap_url = urljoin(base_url, path)
            try:
                urls = await _parse_sitemap(client, sitemap_url, 500)
                all_urls.extend(urls)
            except Exception:
                continue

    # Deduplicate
    return list(set(all_urls))
