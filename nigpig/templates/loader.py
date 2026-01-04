"""Template loader - load YAML vulnerability templates."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class TemplateMatcher:
    """Matcher configuration for template."""

    type: str  # status, word, regex, header
    value: Any
    part: str = "body"  # body, header, all
    negative: bool = False
    condition: str = "or"  # and, or


@dataclass
class TemplateRequest:
    """Request configuration for template."""

    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    follow_redirects: bool = True


@dataclass
class VulnTemplate:
    """Vulnerability template definition."""

    id: str
    name: str
    severity: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    requests: list[TemplateRequest] = field(default_factory=list)
    matchers: list[TemplateMatcher] = field(default_factory=list)
    extractors: list[dict] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "VulnTemplate":
        """Create template from dictionary.

        Args:
            data: Template data dictionary.

        Returns:
            VulnTemplate instance.
        """
        info = data.get("info", {})

        # Parse requests
        requests = []
        for req_data in data.get("requests", []) or data.get("http", []):
            req = TemplateRequest(
                method=req_data.get("method", "GET"),
                path=req_data.get("path", ["/"])[0]
                if isinstance(req_data.get("path"), list)
                else req_data.get("path", "/"),
                headers=req_data.get("headers", {}),
                body=req_data.get("body", ""),
                follow_redirects=req_data.get("redirects", True),
            )
            requests.append(req)

        # Parse matchers
        matchers = []
        for matcher_data in data.get("matchers", []):
            matcher = TemplateMatcher(
                type=matcher_data.get("type", "status"),
                value=matcher_data.get("status")
                or matcher_data.get("words")
                or matcher_data.get("regex"),
                part=matcher_data.get("part", "body"),
                negative=matcher_data.get("negative", False),
                condition=matcher_data.get("condition", "or"),
            )
            matchers.append(matcher)

        return cls(
            id=data.get("id", "unknown"),
            name=info.get("name", "Unknown Template"),
            severity=info.get("severity", "info"),
            description=info.get("description", ""),
            tags=info.get("tags", [])
            if isinstance(info.get("tags"), list)
            else info.get("tags", "").split(","),
            reference=info.get("reference", []),
            requests=requests,
            matchers=matchers,
            extractors=data.get("extractors", []),
        )


class TemplateLoader:
    """Load vulnerability templates from files."""

    def __init__(self, templates_dir: str | Path | None = None):
        """Initialize template loader.

        Args:
            templates_dir: Directory containing templates.
        """
        if templates_dir:
            self.templates_dir = Path(templates_dir)
        else:
            # Default to templates in package
            self.templates_dir = Path(__file__).parent.parent / "vuln_templates"

    def load_all(self) -> list[VulnTemplate]:
        """Load all templates from directory.

        Returns:
            List of loaded templates.
        """
        templates = []

        if not self.templates_dir.exists():
            return templates

        for yaml_file in self.templates_dir.rglob("*.yaml"):
            try:
                template = self.load_file(yaml_file)
                if template:
                    templates.append(template)
            except Exception:
                continue

        return templates

    def load_file(self, path: Path) -> VulnTemplate | None:
        """Load a single template file.

        Args:
            path: Path to YAML file.

        Returns:
            VulnTemplate or None on error.
        """
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if data and isinstance(data, dict):
                return VulnTemplate.from_dict(data)
        except Exception:
            pass

        return None

    def load_by_tags(self, tags: list[str]) -> list[VulnTemplate]:
        """Load templates matching specific tags.

        Args:
            tags: Tags to filter by.

        Returns:
            List of matching templates.
        """
        all_templates = self.load_all()

        matching = []
        for template in all_templates:
            if any(tag in template.tags for tag in tags):
                matching.append(template)

        return matching

    def load_by_severity(self, severities: list[str]) -> list[VulnTemplate]:
        """Load templates matching severity levels.

        Args:
            severities: Severity levels (critical, high, medium, low, info).

        Returns:
            List of matching templates.
        """
        all_templates = self.load_all()

        return [t for t in all_templates if t.severity.lower() in [s.lower() for s in severities]]


# Built-in basic templates
BUILTIN_TEMPLATES = [
    {
        "id": "git-config",
        "info": {
            "name": "Git Config Exposure",
            "severity": "medium",
            "description": "Git configuration file is exposed",
            "tags": ["exposure", "git", "config"],
        },
        "requests": [{"method": "GET", "path": ["/.git/config"]}],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "words", "words": ["[core]", "[remote"]},
        ],
    },
    {
        "id": "env-file",
        "info": {
            "name": "Environment File Exposure",
            "severity": "high",
            "description": ".env file is exposed",
            "tags": ["exposure", "env", "config"],
        },
        "requests": [{"method": "GET", "path": ["/.env"]}],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "regex", "regex": ["(DB_|API_|SECRET_|PASSWORD|KEY)"]},
        ],
    },
    {
        "id": "htaccess",
        "info": {
            "name": ".htaccess Exposure",
            "severity": "low",
            "description": ".htaccess file is exposed",
            "tags": ["exposure", "apache", "config"],
        },
        "requests": [{"method": "GET", "path": ["/.htaccess"]}],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "words", "words": ["RewriteEngine", "RewriteRule", "Deny from"]},
        ],
    },
    {
        "id": "phpinfo",
        "info": {
            "name": "PHP Info Disclosure",
            "severity": "low",
            "description": "phpinfo() page is accessible",
            "tags": ["exposure", "php", "info"],
        },
        "requests": [
            {"method": "GET", "path": ["/phpinfo.php"]},
            {"method": "GET", "path": ["/info.php"]},
        ],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "words", "words": ["PHP Version", "phpinfo()"]},
        ],
    },
    {
        "id": "admin-panel",
        "info": {
            "name": "Admin Panel Found",
            "severity": "info",
            "description": "Admin login panel detected",
            "tags": ["discovery", "admin", "panel"],
        },
        "requests": [
            {"method": "GET", "path": ["/admin"]},
            {"method": "GET", "path": ["/admin/login"]},
            {"method": "GET", "path": ["/administrator"]},
            {"method": "GET", "path": ["/wp-admin"]},
        ],
        "matchers": [
            {"type": "status", "status": [200, 301, 302]},
            {"type": "words", "words": ["login", "password", "admin"], "part": "body"},
        ],
    },
    {
        "id": "debug-enabled",
        "info": {
            "name": "Debug Mode Enabled",
            "severity": "medium",
            "description": "Application debug mode appears to be enabled",
            "tags": ["misc", "debug"],
        },
        "requests": [{"method": "GET", "path": ["/"]}],
        "matchers": [
            {
                "type": "words",
                "words": ["Traceback", "Stack trace", "Debug mode", "DJANGO_SETTINGS_MODULE"],
            },
        ],
    },
    {
        "id": "directory-listing",
        "info": {
            "name": "Directory Listing Enabled",
            "severity": "low",
            "description": "Directory listing is enabled",
            "tags": ["misc", "directory"],
        },
        "requests": [{"method": "GET", "path": ["/images/", "/uploads/", "/files/"]}],
        "matchers": [
            {"type": "status", "status": [200]},
            {"type": "words", "words": ["Index of", "Parent Directory", "[DIR]"]},
        ],
    },
    {
        "id": "backup-files",
        "info": {
            "name": "Backup File Found",
            "severity": "medium",
            "description": "Backup file is accessible",
            "tags": ["exposure", "backup"],
        },
        "requests": [
            {"method": "GET", "path": ["/backup.zip"]},
            {"method": "GET", "path": ["/backup.sql"]},
            {"method": "GET", "path": ["/site.zip"]},
            {"method": "GET", "path": ["/db.sql"]},
        ],
        "matchers": [
            {"type": "status", "status": [200]},
        ],
    },
]


def get_builtin_templates() -> list[VulnTemplate]:
    """Get built-in vulnerability templates.

    Returns:
        List of built-in templates.
    """
    return [VulnTemplate.from_dict(t) for t in BUILTIN_TEMPLATES]
