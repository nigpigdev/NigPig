"""Port scanning - TCP connect scanning with service detection."""

import asyncio
import socket
from dataclasses import dataclass


@dataclass
class PortResult:
    """Result of port scan."""

    port: int
    state: str  # open, closed, filtered
    service: str = ""
    banner: str = ""
    version: str = ""


# Top ports to scan by default
TOP_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1723,
    3306,
    3389,
    5432,
    5900,
    8080,
    8443,
    8888,
    27017,
]

# Common service names
SERVICE_MAP = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    1723: "pptp",
    3306: "mysql",
    3389: "ms-wbt-server",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "sun-answerbook",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


class PortScanner:
    """TCP connect port scanner with rate limiting."""

    def __init__(
        self,
        host: str,
        timeout: float = 2.0,
        max_concurrent: int = 50,
        rate_limit: float = 100.0,
    ):
        """Initialize port scanner.

        Args:
            host: Target host (IP or hostname).
            timeout: Connection timeout per port.
            max_concurrent: Maximum concurrent connections.
            rate_limit: Ports per second limit.
        """
        self.host = host
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.rate_limit = rate_limit
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def scan_top_ports(self) -> list[PortResult]:
        """Scan top common ports.

        Returns:
            List of port scan results (open ports only).
        """
        return await self.scan_ports(TOP_PORTS)

    async def scan_ports(self, ports: list[int]) -> list[PortResult]:
        """Scan specific ports.

        Args:
            ports: List of ports to scan.

        Returns:
            List of open port results.
        """
        results: list[PortResult] = []

        async def scan_single(port: int) -> PortResult | None:
            async with self._semaphore:
                return await self._check_port(port)

        # Scan in batches with rate limiting
        tasks = [scan_single(port) for port in ports]
        batch_results = await asyncio.gather(*tasks)

        for result in batch_results:
            if result and result.state == "open":
                results.append(result)

        return results

    async def scan_range(
        self,
        start_port: int = 1,
        end_port: int = 1024,
    ) -> list[PortResult]:
        """Scan a range of ports.

        Args:
            start_port: Start port (inclusive).
            end_port: End port (inclusive).

        Returns:
            List of open port results.
        """
        ports = list(range(start_port, end_port + 1))
        return await self.scan_ports(ports)

    async def _check_port(self, port: int) -> PortResult | None:
        """Check if a single port is open.

        Args:
            port: Port number.

        Returns:
            PortResult or None if error.
        """
        try:
            # TCP connect scan
            conn = asyncio.open_connection(
                self.host,
                port,
            )

            try:
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)

                # Try to grab banner
                banner = ""
                try:
                    # Send probe for some protocols
                    if port in [80, 8080, 8443]:
                        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    elif port == 22:
                        pass  # SSH sends banner automatically

                    await writer.drain()
                    data = await asyncio.wait_for(
                        reader.read(512),
                        timeout=1.0,
                    )
                    banner = data.decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass

                writer.close()
                await writer.wait_closed()

                service = SERVICE_MAP.get(port, "unknown")
                version = self._extract_version(banner, service)

                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner[:200] if banner else "",
                    version=version,
                )

            except asyncio.TimeoutError:
                return PortResult(port=port, state="filtered")

        except (ConnectionRefusedError, OSError):
            return PortResult(port=port, state="closed")
        except Exception:
            return None

    def _extract_version(self, banner: str, service: str) -> str:
        """Extract version info from banner.

        Args:
            banner: Service banner.
            service: Service name.

        Returns:
            Version string or empty.
        """
        if not banner:
            return ""

        # SSH version
        if service == "ssh" and banner.startswith("SSH-"):
            parts = banner.split()
            if parts:
                return parts[0]

        # HTTP server
        if service in ["http", "https", "http-proxy", "https-alt"]:
            if "Server:" in banner:
                for line in banner.split("\n"):
                    if line.startswith("Server:"):
                        return line.split(":", 1)[1].strip()

        # Generic version extraction
        import re

        version_match = re.search(r"(\d+\.\d+(?:\.\d+)?)", banner)
        if version_match:
            return version_match.group(1)

        return ""


async def quick_scan(host: str, ports: list[int] | None = None) -> list[PortResult]:
    """Quick port scan utility function.

    Args:
        host: Target host.
        ports: Ports to scan (defaults to top ports).

    Returns:
        List of open ports.
    """
    scanner = PortScanner(host)
    if ports:
        return await scanner.scan_ports(ports)
    return await scanner.scan_top_ports()
