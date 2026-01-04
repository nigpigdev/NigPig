"""Template executor - run vulnerability templates against targets."""

import asyncio
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import httpx

from nigpig.templates.loader import VulnTemplate, TemplateMatcher, get_builtin_templates


@dataclass
class TemplateResult:
    """Result of template execution."""

    template_id: str
    template_name: str
    severity: str
    matched: bool
    url: str
    extracted: dict[str, Any] = None
    evidence: str = ""

    def __post_init__(self):
        if self.extracted is None:
            self.extracted = {}


class TemplateExecutor:
    """Execute vulnerability templates against targets."""

    def __init__(
        self,
        timeout: float = 15.0,
        max_concurrent: int = 10,
        rate_limit: float = 10.0,
    ):
        """Initialize template executor.

        Args:
            timeout: Request timeout.
            max_concurrent: Maximum concurrent requests.
            rate_limit: Requests per second.
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._delay = 1.0 / rate_limit

    async def run_template(
        self,
        template: VulnTemplate,
        base_url: str,
    ) -> TemplateResult | None:
        """Run a single template against a target.

        Args:
            template: Template to run.
            base_url: Target base URL.

        Returns:
            TemplateResult if matched, None otherwise.
        """
        async with self._semaphore:
            await asyncio.sleep(self._delay)

            for request in template.requests:
                try:
                    url = urljoin(base_url.rstrip("/") + "/", request.path.lstrip("/"))

                    async with httpx.AsyncClient(
                        timeout=self.timeout,
                        follow_redirects=request.follow_redirects,
                    ) as client:
                        if request.method.upper() == "GET":
                            response = await client.get(url, headers=request.headers)
                        elif request.method.upper() == "POST":
                            response = await client.post(
                                url,
                                headers=request.headers,
                                content=request.body,
                            )
                        else:
                            response = await client.request(
                                request.method,
                                url,
                                headers=request.headers,
                                content=request.body if request.body else None,
                            )

                        # Check matchers
                        if self._check_matchers(template.matchers, response):
                            # Extract data if extractors defined
                            extracted = self._run_extractors(
                                template.extractors,
                                response,
                            )

                            return TemplateResult(
                                template_id=template.id,
                                template_name=template.name,
                                severity=template.severity,
                                matched=True,
                                url=url,
                                extracted=extracted,
                                evidence=f"Status: {response.status_code}",
                            )

                except Exception:
                    continue

        return None

    async def run_all_builtin(self, base_url: str) -> list[TemplateResult]:
        """Run all built-in templates.

        Args:
            base_url: Target base URL.

        Returns:
            List of matched results.
        """
        templates = get_builtin_templates()
        return await self.run_templates(templates, base_url)

    async def run_templates(
        self,
        templates: list[VulnTemplate],
        base_url: str,
    ) -> list[TemplateResult]:
        """Run multiple templates.

        Args:
            templates: Templates to run.
            base_url: Target base URL.

        Returns:
            List of matched results.
        """
        tasks = [self.run_template(t, base_url) for t in templates]
        results = await asyncio.gather(*tasks)

        return [r for r in results if r is not None]

    async def run_by_severity(
        self,
        templates: list[VulnTemplate],
        base_url: str,
        min_severity: str = "info",
    ) -> list[TemplateResult]:
        """Run templates filtered by minimum severity.

        Args:
            templates: Templates to run.
            base_url: Target base URL.
            min_severity: Minimum severity level.

        Returns:
            List of matched results.
        """
        severity_order = ["info", "low", "medium", "high", "critical"]
        min_index = (
            severity_order.index(min_severity.lower())
            if min_severity.lower() in severity_order
            else 0
        )

        filtered = [t for t in templates if severity_order.index(t.severity.lower()) >= min_index]

        return await self.run_templates(filtered, base_url)

    def _check_matchers(
        self,
        matchers: list[TemplateMatcher],
        response: httpx.Response,
    ) -> bool:
        """Check if response matches template matchers.

        Args:
            matchers: List of matchers.
            response: HTTP response.

        Returns:
            True if all matchers pass.
        """
        if not matchers:
            return False

        # Determine match condition (and/or)
        condition = matchers[0].condition if matchers else "or"

        results = []
        for matcher in matchers:
            matched = self._check_single_matcher(matcher, response)
            if matcher.negative:
                matched = not matched
            results.append(matched)

        if condition == "and":
            return all(results)
        return any(results)

    def _check_single_matcher(
        self,
        matcher: TemplateMatcher,
        response: httpx.Response,
    ) -> bool:
        """Check a single matcher.

        Args:
            matcher: Matcher to check.
            response: HTTP response.

        Returns:
            True if matched.
        """
        if matcher.type == "status":
            if isinstance(matcher.value, list):
                return response.status_code in matcher.value
            return response.status_code == matcher.value

        # Get content to match against
        if matcher.part == "header":
            content = str(dict(response.headers))
        elif matcher.part == "all":
            content = str(dict(response.headers)) + response.text
        else:  # body
            content = response.text

        content_lower = content.lower()

        if matcher.type == "words":
            words = matcher.value if isinstance(matcher.value, list) else [matcher.value]
            return any(word.lower() in content_lower for word in words)

        if matcher.type == "regex":
            patterns = matcher.value if isinstance(matcher.value, list) else [matcher.value]
            for pattern in patterns:
                try:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
                except Exception:
                    pass
            return False

        return False

    def _run_extractors(
        self,
        extractors: list[dict],
        response: httpx.Response,
    ) -> dict[str, Any]:
        """Run data extractors on response.

        Args:
            extractors: Extractor definitions.
            response: HTTP response.

        Returns:
            Extracted data.
        """
        extracted: dict[str, Any] = {}

        for extractor in extractors:
            ext_type = extractor.get("type", "regex")
            name = extractor.get("name", "extracted")

            if ext_type == "regex":
                patterns = extractor.get("regex", [])
                for pattern in patterns:
                    try:
                        match = re.search(pattern, response.text)
                        if match:
                            extracted[name] = match.group(1) if match.groups() else match.group(0)
                            break
                    except Exception:
                        pass

            elif ext_type == "kval":
                # Key-value extraction from headers
                keys = extractor.get("kval", [])
                for key in keys:
                    value = response.headers.get(key)
                    if value:
                        extracted[name] = value
                        break

        return extracted


async def quick_scan(url: str) -> list[TemplateResult]:
    """Quick vulnerability scan with built-in templates.

    Args:
        url: Target URL.

    Returns:
        List of findings.
    """
    executor = TemplateExecutor()
    return await executor.run_all_builtin(url)
