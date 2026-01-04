"""SQLite database for scan data and findings."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import aiosqlite


class Database:
    """Async SQLite database wrapper for NigPig."""

    def __init__(self, db_path: Path):
        """Initialize database.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def __aenter__(self) -> "Database":
        """Async context manager entry."""
        self._conn = await aiosqlite.connect(self.db_path)
        self._conn.row_factory = aiosqlite.Row
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._conn:
            await self._conn.close()

    async def init_schema(self) -> None:
        """Initialize database schema."""
        if not self._conn:
            raise RuntimeError("Database not connected")

        await self._conn.executescript("""
            -- Scan runs table
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT UNIQUE NOT NULL,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT DEFAULT 'running',
                started_at TEXT NOT NULL,
                completed_at TEXT,
                total_urls INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                summary_json TEXT
            );
            
            -- Discovered URLs
            CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                url TEXT NOT NULL,
                normalized_url TEXT,
                endpoint_type TEXT,
                discovered_at TEXT NOT NULL,
                status_code INTEGER,
                FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
            );
            
            -- Findings/vulnerabilities
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                source TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                url TEXT,
                param TEXT,
                evidence TEXT,
                remediation TEXT,
                cweid TEXT,
                owasp_category TEXT,
                detected_at TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0,
                is_false_positive INTEGER DEFAULT 0,
                FOREIGN KEY (run_id) REFERENCES scan_runs(run_id)
            );
            
            -- Evidence storage (masked)
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id INTEGER NOT NULL,
                evidence_type TEXT NOT NULL,
                content TEXT NOT NULL,
                is_masked INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            );
            
            -- Create indexes
            CREATE INDEX IF NOT EXISTS idx_urls_run_id ON urls(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        """)
        await self._conn.commit()

    async def create_run(
        self,
        run_id: str,
        target: str,
        profile: str,
    ) -> None:
        """Create a new scan run record.

        Args:
            run_id: Unique run identifier.
            target: Target URL.
            profile: Scan profile name.
        """
        if not self._conn:
            raise RuntimeError("Database not connected")

        await self._conn.execute(
            """
            INSERT INTO scan_runs (run_id, target, profile, started_at)
            VALUES (?, ?, ?, ?)
            """,
            (run_id, target, profile, datetime.now().isoformat()),
        )
        await self._conn.commit()

    async def update_run_status(
        self,
        run_id: str,
        status: str,
        summary: Optional[dict[str, Any]] = None,
    ) -> None:
        """Update scan run status.

        Args:
            run_id: Run identifier.
            status: New status.
            summary: Optional summary data.
        """
        if not self._conn:
            raise RuntimeError("Database not connected")

        summary_json = json.dumps(summary) if summary else None

        await self._conn.execute(
            """
            UPDATE scan_runs 
            SET status = ?, 
                completed_at = ?,
                total_urls = ?,
                total_findings = ?,
                summary_json = ?
            WHERE run_id = ?
            """,
            (
                status,
                datetime.now().isoformat(),
                summary.get("total_urls", 0) if summary else 0,
                len(summary.get("findings", [])) if summary else 0,
                summary_json,
                run_id,
            ),
        )
        await self._conn.commit()

    async def save_url(self, run_id: str, url: str, status_code: Optional[int] = None) -> None:
        """Save a discovered URL.

        Args:
            run_id: Run identifier.
            url: Discovered URL.
            status_code: Optional HTTP status code.
        """
        if not self._conn:
            raise RuntimeError("Database not connected")

        from nigpig.discovery.url_utils import normalize_url, classify_endpoint

        await self._conn.execute(
            """
            INSERT INTO urls (run_id, url, normalized_url, endpoint_type, discovered_at, status_code)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                url,
                normalize_url(url),
                classify_endpoint(url),
                datetime.now().isoformat(),
                status_code,
            ),
        )
        await self._conn.commit()

    async def save_finding(self, run_id: str, finding: dict[str, Any]) -> int:
        """Save a security finding.

        Args:
            run_id: Run identifier.
            finding: Finding dictionary.

        Returns:
            Finding ID.
        """
        if not self._conn:
            raise RuntimeError("Database not connected")

        cursor = await self._conn.execute(
            """
            INSERT INTO findings (
                run_id, source, name, description, severity,
                url, param, evidence, remediation, cweid,
                owasp_category, detected_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                finding.get("source", "unknown"),
                finding.get("name", "Unknown Finding"),
                finding.get("description", ""),
                finding.get("severity", "info"),
                finding.get("url", ""),
                finding.get("param", ""),
                finding.get("evidence", ""),
                finding.get("remediation", finding.get("solution", "")),
                finding.get("cweid", ""),
                finding.get("owasp_category", ""),
                datetime.now().isoformat(),
            ),
        )
        await self._conn.commit()
        return cursor.lastrowid or 0

    async def get_findings(
        self,
        run_id: str,
        severity: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Get findings for a run.

        Args:
            run_id: Run identifier.
            severity: Optional severity filter.

        Returns:
            List of finding dictionaries.
        """
        if not self._conn:
            raise RuntimeError("Database not connected")

        query = "SELECT * FROM findings WHERE run_id = ?"
        params: list[Any] = [run_id]

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += (
            " ORDER BY CASE severity "
            "WHEN 'critical' THEN 1 "
            "WHEN 'high' THEN 2 "
            "WHEN 'medium' THEN 3 "
            "WHEN 'low' THEN 4 "
            "ELSE 5 END"
        )

        cursor = await self._conn.execute(query, params)
        rows = await cursor.fetchall()

        return [dict(row) for row in rows]

    async def get_run_summary(self, run_id: str) -> Optional[dict[str, Any]]:
        """Get run summary.

        Args:
            run_id: Run identifier.

        Returns:
            Run summary dictionary or None.
        """
        if not self._conn:
            raise RuntimeError("Database not connected")

        cursor = await self._conn.execute(
            "SELECT * FROM scan_runs WHERE run_id = ?",
            (run_id,),
        )
        row = await cursor.fetchone()

        if row:
            result = dict(row)
            if result.get("summary_json"):
                result["summary"] = json.loads(result["summary_json"])
            return result
        return None
