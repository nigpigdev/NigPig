"""Storage module - SQLite database for findings and scan data."""

from nigpig.storage.db import Database
from nigpig.storage.masking import mask_sensitive_data

__all__ = ["Database", "mask_sensitive_data"]
