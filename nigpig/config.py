"""Configuration loading and management."""

from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG_PATHS = [
    Path("configs/default.yaml"),
    Path("nigpig.yaml"),
    Path.home() / ".nigpig" / "config.yaml",
]


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load configuration from file.

    Args:
        config_path: Optional path to config file. If not provided,
                    searches default locations.

    Returns:
        Configuration dictionary.

    Raises:
        FileNotFoundError: If no config file is found.
    """
    paths_to_try = [config_path] if config_path else DEFAULT_CONFIG_PATHS

    for path in paths_to_try:
        if path.exists():
            with open(path, encoding="utf-8") as f:
                config = yaml.safe_load(f)
                return config or {}

    # Return minimal default config if no file found
    return get_default_config()


def get_default_config() -> dict[str, Any]:
    """Return minimal default configuration."""
    return {
        "zap": {
            "host": "localhost",
            "port": 8080,
            "api_key": "",
        },
        "rate_limits": {
            "requests_per_second": 10,
            "max_concurrency": 5,
            "timebox_minutes": 30,
            "max_urls": 500,
        },
        "scope": {
            "same_origin_only": True,
            "respect_robots_txt": True,
            "allowed_methods": ["GET", "HEAD", "OPTIONS"],
            "blocked_methods": ["PUT", "DELETE", "PATCH", "POST"],
        },
        "profiles": {
            "safe": {
                "spider_max_depth": 2,
                "spider_max_duration": 5,
                "ajax_spider_enabled": False,
                "active_scan_enabled": False,
                "timebox_minutes": 15,
                "requests_per_second": 5,
            },
            "balanced": {
                "spider_max_depth": 5,
                "spider_max_duration": 10,
                "ajax_spider_enabled": True,
                "ajax_spider_max_duration": 5,
                "active_scan_enabled": True,
                "active_scan_policy": "Light",
                "timebox_minutes": 30,
                "requests_per_second": 10,
            },
            "deep": {
                "spider_max_depth": 10,
                "spider_max_duration": 20,
                "ajax_spider_enabled": True,
                "ajax_spider_max_duration": 15,
                "active_scan_enabled": True,
                "active_scan_policy": "Medium",
                "timebox_minutes": 60,
                "requests_per_second": 15,
                "max_urls": 1000,
            },
        },
    }


def get_profile(config: dict[str, Any], profile_name: str) -> dict[str, Any]:
    """Get a specific scan profile configuration.

    Args:
        config: Full configuration dictionary.
        profile_name: Name of the profile (safe, balanced, deep).

    Returns:
        Profile configuration dictionary.
    """
    profiles = config.get("profiles", get_default_config()["profiles"])
    return profiles.get(profile_name, profiles["balanced"])


def merge_configs(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge two configuration dictionaries.

    Args:
        base: Base configuration.
        override: Override configuration (takes precedence).

    Returns:
        Merged configuration.
    """
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value

    return result
