"""Secret scanner - scan files and directories for secrets."""

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import AsyncIterator

from nigpig.secrets.patterns import scan_for_secrets


@dataclass
class SecretFinding:
    """A detected secret in a file."""

    file_path: str
    secret_type: str
    value: str
    severity: str
    line: int
    context: str = ""
    description: str = ""


class SecretScanner:
    """Scan files and directories for secrets."""

    # File extensions to scan
    SCANNABLE_EXTENSIONS = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".cs",
        ".cpp",
        ".c",
        ".h",
        ".hpp",
        ".rs",
        ".swift",
        ".kt",
        ".scala",
        ".json",
        ".yaml",
        ".yml",
        ".xml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".env",
        ".properties",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".bat",
        ".cmd",
        ".sql",
        ".tf",
        ".tfvars",
        ".hcl",
        ".dockerfile",
        ".md",
        ".txt",
        ".log",
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".less",
        ".vue",
        ".svelte",
    }

    # Directories to skip
    SKIP_DIRS = {
        "node_modules",
        ".git",
        ".svn",
        ".hg",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
        ".venv",
        "venv",
        "env",
        ".env",
        "vendor",
        "dist",
        "build",
        "target",
        "out",
        ".idea",
        ".vscode",
        ".vs",
        "coverage",
        ".nyc_output",
        "logs",
    }

    # Max file size to scan (5MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024

    def __init__(self, max_concurrent: int = 10):
        """Initialize secret scanner.

        Args:
            max_concurrent: Maximum concurrent file reads.
        """
        self.max_concurrent = max_concurrent
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def scan_file(self, file_path: Path | str) -> list[SecretFinding]:
        """Scan a single file for secrets.

        Args:
            file_path: Path to file.

        Returns:
            List of findings in the file.
        """
        file_path = Path(file_path)
        findings: list[SecretFinding] = []

        try:
            # Check file size
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return findings

            # Check extension
            if file_path.suffix.lower() not in self.SCANNABLE_EXTENSIONS:
                # Still scan extensionless files
                if file_path.suffix:
                    return findings

            async with self._semaphore:
                import aiofiles

                async with aiofiles.open(file_path, "r", errors="ignore") as f:
                    content = await f.read()

                secrets = scan_for_secrets(content)

                for secret in secrets:
                    findings.append(
                        SecretFinding(
                            file_path=str(file_path),
                            secret_type=secret["type"],
                            value=secret["value"],
                            severity=secret["severity"],
                            line=secret["line"],
                            context=secret["context"],
                            description=secret.get("description", ""),
                        )
                    )

        except Exception:
            pass

        return findings

    async def scan_directory(
        self,
        directory: Path | str,
        recursive: bool = True,
        max_files: int = 10000,
    ) -> AsyncIterator[SecretFinding]:
        """Scan a directory for secrets.

        Args:
            directory: Directory path.
            recursive: Whether to scan subdirectories.
            max_files: Maximum files to scan.

        Yields:
            SecretFinding for each discovered secret.
        """
        directory = Path(directory)
        file_count = 0

        if recursive:
            files_iter = directory.rglob("*")
        else:
            files_iter = directory.glob("*")

        batch: list[Path] = []

        for file_path in files_iter:
            if file_count >= max_files:
                break

            # Skip directories
            if file_path.is_dir():
                continue

            # Skip excluded directories
            if any(skip in file_path.parts for skip in self.SKIP_DIRS):
                continue

            batch.append(file_path)
            file_count += 1

            # Process in batches
            if len(batch) >= self.max_concurrent:
                async for finding in self._process_batch(batch):
                    yield finding
                batch = []

        # Process remaining files
        if batch:
            async for finding in self._process_batch(batch):
                yield finding

    async def _process_batch(
        self,
        files: list[Path],
    ) -> AsyncIterator[SecretFinding]:
        """Process a batch of files.

        Args:
            files: List of file paths.

        Yields:
            SecretFinding from each file.
        """
        tasks = [self.scan_file(f) for f in files]
        results = await asyncio.gather(*tasks)

        for findings in results:
            for finding in findings:
                yield finding

    async def scan_content(
        self,
        content: str,
        source: str = "inline",
    ) -> list[SecretFinding]:
        """Scan raw content for secrets.

        Args:
            content: Text content to scan.
            source: Source identifier.

        Returns:
            List of findings.
        """
        findings: list[SecretFinding] = []

        secrets = scan_for_secrets(content)

        for secret in secrets:
            findings.append(
                SecretFinding(
                    file_path=source,
                    secret_type=secret["type"],
                    value=secret["value"],
                    severity=secret["severity"],
                    line=secret["line"],
                    context=secret["context"],
                    description=secret.get("description", ""),
                )
            )

        return findings

    async def get_summary(
        self,
        directory: Path | str,
    ) -> dict:
        """Get summary of secrets in directory.

        Args:
            directory: Directory to scan.

        Returns:
            Summary dictionary.
        """
        findings_by_severity: dict[str, list[SecretFinding]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
        }

        findings_by_type: dict[str, int] = {}

        async for finding in self.scan_directory(directory):
            severity = finding.severity.lower()
            if severity in findings_by_severity:
                findings_by_severity[severity].append(finding)

            findings_by_type[finding.secret_type] = findings_by_type.get(finding.secret_type, 0) + 1

        total = sum(len(f) for f in findings_by_severity.values())

        return {
            "total": total,
            "by_severity": {k: len(v) for k, v in findings_by_severity.items()},
            "by_type": findings_by_type,
            "critical_count": len(findings_by_severity["critical"]),
            "high_count": len(findings_by_severity["high"]),
        }


async def quick_scan(path: str | Path) -> list[SecretFinding]:
    """Quick secret scan of a file or directory.

    Args:
        path: File or directory path.

    Returns:
        List of all findings.
    """
    scanner = SecretScanner()
    path = Path(path)

    if path.is_file():
        return await scanner.scan_file(path)

    findings = []
    async for finding in scanner.scan_directory(path):
        findings.append(finding)

    return findings
