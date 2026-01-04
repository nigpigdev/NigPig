"""Subdomain enumeration - passive and active discovery."""

import asyncio
import re
from dataclasses import dataclass
from typing import AsyncIterator
from urllib.parse import urlparse

import httpx


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration."""

    subdomain: str
    source: str
    resolved: bool = False
    ip_addresses: list[str] | None = None


class SubdomainEnumerator:
    """Enumerate subdomains using multiple passive sources."""

    # Common subdomain prefixes for brute-force
    COMMON_PREFIXES = [
        "www",
        "mail",
        "ftp",
        "localhost",
        "webmail",
        "smtp",
        "pop",
        "ns1",
        "ns2",
        "webdisk",
        "cpanel",
        "whm",
        "autodiscover",
        "autoconfig",
        "m",
        "mobile",
        "api",
        "dev",
        "staging",
        "test",
        "beta",
        "demo",
        "admin",
        "portal",
        "blog",
        "shop",
        "store",
        "app",
        "cdn",
        "static",
        "assets",
        "img",
        "images",
        "media",
        "video",
        "docs",
        "help",
        "support",
        "status",
        "monitor",
        "vpn",
        "remote",
        "gateway",
        "proxy",
        "cache",
        "backup",
        "db",
        "database",
        "mysql",
        "postgres",
        "redis",
        "elastic",
        "kafka",
        "rabbit",
        "mq",
        "jenkins",
        "gitlab",
        "github",
        "bitbucket",
        "jira",
        "confluence",
        "grafana",
        "kibana",
        "prometheus",
        "nagios",
        "zabbix",
        "splunk",
        "sso",
        "auth",
        "login",
        "oauth",
        "id",
        "identity",
        "cas",
        "adfs",
        "exchange",
        "owa",
        "outlook",
        "teams",
        "sharepoint",
        "onedrive",
        "s3",
        "storage",
        "files",
        "download",
        "upload",
        "cloud",
        "aws",
        "azure",
        "gcp",
        "internal",
        "intranet",
        "extranet",
        "corp",
        "corporate",
        "office",
        "hr",
        "finance",
        "sales",
        "marketing",
        "legal",
        "it",
        "ops",
        "devops",
        "stage",
        "uat",
        "qa",
        "prod",
        "production",
        "sandbox",
        "lab",
        "v1",
        "v2",
        "v3",
        "api-v1",
        "api-v2",
        "old",
        "new",
        "legacy",
        "www2",
        "www3",
        "web",
        "web1",
        "web2",
        "server",
        "server1",
        "server2",
    ]

    def __init__(
        self,
        domain: str,
        timeout: int = 10,
        max_concurrent: int = 20,
        rate_limit: float = 10.0,
    ):
        """Initialize subdomain enumerator.

        Args:
            domain: Target domain.
            timeout: Request timeout.
            max_concurrent: Maximum concurrent requests.
            rate_limit: Requests per second limit.
        """
        self.domain = self._extract_domain(domain)
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._found: set[str] = set()

    def _extract_domain(self, target: str) -> str:
        """Extract base domain from URL or domain string."""
        if "://" in target:
            parsed = urlparse(target)
            return parsed.netloc.split(":")[0]
        return target.split(":")[0]

    async def enumerate_all(self) -> list[SubdomainResult]:
        """Run all enumeration methods.

        Returns:
            List of discovered subdomains.
        """
        results: list[SubdomainResult] = []

        # Run passive sources concurrently
        passive_tasks = [
            self._crtsh(),
            self._hackertarget(),
            self._urlscan(),
        ]

        passive_results = await asyncio.gather(*passive_tasks, return_exceptions=True)

        for result in passive_results:
            if isinstance(result, list):
                results.extend(result)
                for r in result:
                    self._found.add(r.subdomain)

        # Brute-force common prefixes
        brute_results = await self._brute_force_common()
        results.extend(brute_results)

        # Deduplicate
        seen = set()
        unique = []
        for r in results:
            if r.subdomain not in seen:
                seen.add(r.subdomain)
                unique.append(r)

        return unique

    async def _crtsh(self) -> list[SubdomainResult]:
        """Query crt.sh certificate transparency logs."""
        results = []
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for subdomain in name.split("\n"):
                            subdomain = subdomain.strip().lower()
                            if subdomain.endswith(self.domain) and "*" not in subdomain:
                                if subdomain not in self._found:
                                    results.append(
                                        SubdomainResult(
                                            subdomain=subdomain,
                                            source="crt.sh",
                                        )
                                    )
        except Exception:
            pass

        return results

    async def _hackertarget(self) -> list[SubdomainResult]:
        """Query HackerTarget API."""
        results = []
        url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                if response.status_code == 200 and "error" not in response.text.lower():
                    for line in response.text.split("\n"):
                        if "," in line:
                            subdomain = line.split(",")[0].strip().lower()
                            if subdomain.endswith(self.domain):
                                if subdomain not in self._found:
                                    results.append(
                                        SubdomainResult(
                                            subdomain=subdomain,
                                            source="hackertarget",
                                        )
                                    )
        except Exception:
            pass

        return results

    async def _urlscan(self) -> list[SubdomainResult]:
        """Query urlscan.io API."""
        results = []
        url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url)
                if response.status_code == 200:
                    data = response.json()
                    for result in data.get("results", []):
                        page = result.get("page", {})
                        domain = page.get("domain", "").lower()
                        if domain.endswith(self.domain):
                            if domain not in self._found:
                                results.append(
                                    SubdomainResult(
                                        subdomain=domain,
                                        source="urlscan.io",
                                    )
                                )
        except Exception:
            pass

        return results

    async def _brute_force_common(self) -> list[SubdomainResult]:
        """Brute-force common subdomain prefixes."""
        results = []

        async def check_subdomain(prefix: str) -> SubdomainResult | None:
            subdomain = f"{prefix}.{self.domain}"
            if subdomain in self._found:
                return None

            async with self._semaphore:
                try:
                    import dns.asyncresolver

                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 3
                    resolver.lifetime = 3

                    answers = await resolver.resolve(subdomain, "A")
                    ips = [str(rdata) for rdata in answers]

                    return SubdomainResult(
                        subdomain=subdomain,
                        source="brute-force",
                        resolved=True,
                        ip_addresses=ips,
                    )
                except Exception:
                    return None

        # Rate-limited execution
        tasks = []
        for prefix in self.COMMON_PREFIXES:
            tasks.append(check_subdomain(prefix))
            if len(tasks) >= self.max_concurrent:
                batch_results = await asyncio.gather(*tasks)
                for r in batch_results:
                    if r:
                        results.append(r)
                        self._found.add(r.subdomain)
                tasks = []
                await asyncio.sleep(1 / self.rate_limit)

        if tasks:
            batch_results = await asyncio.gather(*tasks)
            for r in batch_results:
                if r:
                    results.append(r)

        return results

    async def enumerate_with_wordlist(
        self,
        wordlist_path: str,
        max_entries: int = 10000,
    ) -> AsyncIterator[SubdomainResult]:
        """Enumerate using a wordlist file.

        Args:
            wordlist_path: Path to wordlist file.
            max_entries: Maximum entries to process.

        Yields:
            SubdomainResult for each discovered subdomain.
        """
        import aiofiles

        try:
            async with aiofiles.open(wordlist_path, "r") as f:
                count = 0
                async for line in f:
                    if count >= max_entries:
                        break

                    prefix = line.strip().lower()
                    if not prefix or prefix.startswith("#"):
                        continue

                    subdomain = f"{prefix}.{self.domain}"
                    if subdomain in self._found:
                        continue

                    async with self._semaphore:
                        try:
                            import dns.asyncresolver

                            resolver = dns.asyncresolver.Resolver()
                            resolver.timeout = 2
                            resolver.lifetime = 2

                            answers = await resolver.resolve(subdomain, "A")
                            ips = [str(rdata) for rdata in answers]

                            self._found.add(subdomain)
                            yield SubdomainResult(
                                subdomain=subdomain,
                                source="wordlist",
                                resolved=True,
                                ip_addresses=ips,
                            )
                        except Exception:
                            pass

                    count += 1
                    if count % self.max_concurrent == 0:
                        await asyncio.sleep(1 / self.rate_limit)

        except FileNotFoundError:
            pass
