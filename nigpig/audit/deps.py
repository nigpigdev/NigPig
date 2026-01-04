"""Dependency scanning - check for vulnerable packages."""

import asyncio
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class VulnerableDep:
    """A vulnerable dependency."""

    name: str
    version: str
    vulnerability_id: str
    severity: str
    description: str
    fixed_version: str = ""


class DependencyScanner:
    """Scan project dependencies for vulnerabilities."""

    def __init__(self):
        """Initialize dependency scanner."""
        pass

    async def scan_python(
        self,
        project_path: Path | str,
    ) -> list[VulnerableDep]:
        """Scan Python dependencies using pip-audit.

        Args:
            project_path: Path to Python project.

        Returns:
            List of vulnerable dependencies.
        """
        project_path = Path(project_path)
        vulnerabilities = []

        # Check for requirements.txt or pyproject.toml
        req_file = None
        if (project_path / "requirements.txt").exists():
            req_file = project_path / "requirements.txt"
        elif (project_path / "pyproject.toml").exists():
            req_file = project_path / "pyproject.toml"

        if not req_file:
            return vulnerabilities

        try:
            # Run pip-audit
            result = await asyncio.to_thread(
                subprocess.run,
                ["pip-audit", "-r", str(req_file), "--format", "json"],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                for vuln in data.get("dependencies", []):
                    for v in vuln.get("vulns", []):
                        vulnerabilities.append(
                            VulnerableDep(
                                name=vuln.get("name", ""),
                                version=vuln.get("version", ""),
                                vulnerability_id=v.get("id", ""),
                                severity=v.get("severity", "unknown"),
                                description=v.get("description", "")[:200],
                                fixed_version=v.get("fix_versions", [""])[0]
                                if v.get("fix_versions")
                                else "",
                            )
                        )

        except FileNotFoundError:
            pass  # pip-audit not installed
        except Exception:
            pass

        return vulnerabilities

    async def scan_npm(
        self,
        project_path: Path | str,
    ) -> list[VulnerableDep]:
        """Scan Node.js dependencies using npm audit.

        Args:
            project_path: Path to Node.js project.

        Returns:
            List of vulnerable dependencies.
        """
        project_path = Path(project_path)
        vulnerabilities = []

        if not (project_path / "package.json").exists():
            return vulnerabilities

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["npm", "audit", "--json"],
                cwd=str(project_path),
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                vulns = data.get("vulnerabilities", {})

                for name, info in vulns.items():
                    severity_map = {
                        "critical": "critical",
                        "high": "high",
                        "moderate": "medium",
                        "low": "low",
                    }

                    vulnerabilities.append(
                        VulnerableDep(
                            name=name,
                            version=info.get("range", ""),
                            vulnerability_id=info.get("via", [{}])[0].get("url", "")
                            if isinstance(info.get("via", [{}])[0], dict)
                            else "",
                            severity=severity_map.get(info.get("severity", ""), "unknown"),
                            description=info.get("via", [{}])[0].get("title", "")
                            if isinstance(info.get("via", [{}])[0], dict)
                            else str(info.get("via", "")),
                            fixed_version=info.get("fixAvailable", {}).get("version", "")
                            if isinstance(info.get("fixAvailable"), dict)
                            else "",
                        )
                    )

        except FileNotFoundError:
            pass  # npm not installed
        except Exception:
            pass

        return vulnerabilities

    async def scan_all(
        self,
        project_path: Path | str,
    ) -> dict[str, list[VulnerableDep]]:
        """Scan all supported dependency types.

        Args:
            project_path: Path to project.

        Returns:
            Dictionary of language to vulnerabilities.
        """
        project_path = Path(project_path)

        results = {}

        # Scan Python
        python_vulns = await self.scan_python(project_path)
        if python_vulns:
            results["python"] = python_vulns

        # Scan NPM
        npm_vulns = await self.scan_npm(project_path)
        if npm_vulns:
            results["npm"] = npm_vulns

        return results

    def get_summary(
        self,
        vulnerabilities: list[VulnerableDep],
    ) -> dict:
        """Get vulnerability summary.

        Args:
            vulnerabilities: List of vulnerabilities.

        Returns:
            Summary dictionary.
        """
        by_severity = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for vuln in vulnerabilities:
            sev = vuln.severity.lower()
            if sev in by_severity:
                by_severity[sev] += 1

        return {
            "total": len(vulnerabilities),
            "by_severity": by_severity,
            "critical_count": by_severity["critical"],
            "high_count": by_severity["high"],
        }


async def quick_dep_scan(path: str | Path) -> dict:
    """Quick dependency scan.

    Args:
        path: Project path.

    Returns:
        Scan results.
    """
    scanner = DependencyScanner()
    return await scanner.scan_all(path)
