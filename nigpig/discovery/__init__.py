"""Discovery module - URL discovery and enumeration."""

from nigpig.discovery.robots import parse_robots_txt
from nigpig.discovery.sitemap import fetch_sitemap_urls
from nigpig.discovery.url_utils import deduplicate_urls, is_same_origin, normalize_url

__all__ = [
    "fetch_sitemap_urls",
    "parse_robots_txt",
    "normalize_url",
    "deduplicate_urls",
    "is_same_origin",
]
