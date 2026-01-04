"""DNS resolution and record enumeration."""

import asyncio
from dataclasses import dataclass
from typing import Any

try:
    import dns.asyncresolver
    import dns.rdatatype

    HAS_DNS = True
except ImportError:
    HAS_DNS = False


@dataclass
class DNSRecord:
    """DNS record information."""

    record_type: str
    name: str
    value: str
    ttl: int = 0


class DNSResolver:
    """Async DNS resolution and record enumeration."""

    RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]

    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 5.0,
    ):
        """Initialize DNS resolver.

        Args:
            nameservers: Custom nameservers (defaults to system).
            timeout: Query timeout.
        """
        if not HAS_DNS:
            raise ImportError("dnspython not installed. Run: pip install dnspython")

        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

        if nameservers:
            self.resolver.nameservers = nameservers

    async def resolve(
        self,
        domain: str,
        record_type: str = "A",
    ) -> list[DNSRecord]:
        """Resolve DNS records.

        Args:
            domain: Domain to resolve.
            record_type: DNS record type.

        Returns:
            List of DNS records.
        """
        records = []

        try:
            answers = await self.resolver.resolve(domain, record_type)
            for rdata in answers:
                records.append(
                    DNSRecord(
                        record_type=record_type,
                        name=domain,
                        value=str(rdata),
                        ttl=answers.rrset.ttl if answers.rrset else 0,
                    )
                )
        except Exception:
            pass

        return records

    async def enumerate_all(self, domain: str) -> dict[str, list[DNSRecord]]:
        """Enumerate all common DNS record types.

        Args:
            domain: Domain to enumerate.

        Returns:
            Dictionary of record type to records.
        """
        results: dict[str, list[DNSRecord]] = {}

        tasks = []
        for record_type in self.RECORD_TYPES:
            tasks.append(self._resolve_with_type(domain, record_type))

        all_results = await asyncio.gather(*tasks)

        for record_type, records in zip(self.RECORD_TYPES, all_results):
            if records:
                results[record_type] = records

        return results

    async def _resolve_with_type(
        self,
        domain: str,
        record_type: str,
    ) -> list[DNSRecord]:
        """Helper to resolve with type for gather."""
        return await self.resolve(domain, record_type)

    async def get_nameservers(self, domain: str) -> list[str]:
        """Get nameservers for domain.

        Args:
            domain: Domain name.

        Returns:
            List of nameserver hostnames.
        """
        records = await self.resolve(domain, "NS")
        return [r.value.rstrip(".") for r in records]

    async def get_mx_records(self, domain: str) -> list[tuple[int, str]]:
        """Get MX records with priority.

        Args:
            domain: Domain name.

        Returns:
            List of (priority, hostname) tuples.
        """
        try:
            answers = await self.resolver.resolve(domain, "MX")
            return [(rdata.preference, str(rdata.exchange).rstrip(".")) for rdata in answers]
        except Exception:
            return []

    async def reverse_lookup(self, ip: str) -> str | None:
        """Reverse DNS lookup.

        Args:
            ip: IP address.

        Returns:
            Hostname or None.
        """
        try:
            from dns.reversename import from_address

            rev_name = from_address(ip)
            answers = await self.resolver.resolve(rev_name, "PTR")
            if answers:
                return str(answers[0]).rstrip(".")
        except Exception:
            pass
        return None

    async def check_zone_transfer(self, domain: str) -> list[DNSRecord] | None:
        """Attempt zone transfer (AXFR).

        Note: Will fail on properly configured servers.

        Args:
            domain: Domain name.

        Returns:
            List of records if transfer allowed, None otherwise.
        """
        # Zone transfer is typically blocked; this is for detection only
        nameservers = await self.get_nameservers(domain)

        for ns in nameservers[:2]:  # Try first 2 nameservers
            try:
                import dns.query
                import dns.zone

                # Resolve NS to IP
                ns_ips = await self.resolve(ns, "A")
                if not ns_ips:
                    continue

                ns_ip = ns_ips[0].value

                # Attempt transfer (will likely fail)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))

                records = []
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append(
                                DNSRecord(
                                    record_type=dns.rdatatype.to_text(rdataset.rdtype),
                                    name=str(name) + "." + domain,
                                    value=str(rdata),
                                    ttl=rdataset.ttl,
                                )
                            )

                return records

            except Exception:
                continue

        return None


async def resolve_domains(
    domains: list[str],
    record_type: str = "A",
    max_concurrent: int = 50,
) -> dict[str, list[str]]:
    """Bulk resolve multiple domains.

    Args:
        domains: List of domains.
        record_type: Record type to query.
        max_concurrent: Max concurrent queries.

    Returns:
        Dictionary of domain to resolved values.
    """
    resolver = DNSResolver()
    semaphore = asyncio.Semaphore(max_concurrent)
    results: dict[str, list[str]] = {}

    async def resolve_one(domain: str) -> tuple[str, list[str]]:
        async with semaphore:
            records = await resolver.resolve(domain, record_type)
            return domain, [r.value for r in records]

    tasks = [resolve_one(d) for d in domains]
    all_results = await asyncio.gather(*tasks)

    for domain, values in all_results:
        if values:
            results[domain] = values

    return results
