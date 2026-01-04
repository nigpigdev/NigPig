"""Recon API routes - subdomain, ports, DNS."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class SubdomainRequest(BaseModel):
    domain: str
    use_ct_logs: bool = True
    brute_force: bool = True


class PortScanRequest(BaseModel):
    host: str
    ports: list[int] | None = None


@router.post("/subdomain")
async def subdomain_enum(request: SubdomainRequest):
    """Enumerate subdomains."""
    from nigpig.recon.subdomain import SubdomainEnumerator

    enumerator = SubdomainEnumerator(request.domain)
    subdomains = await enumerator.enumerate_all()

    return {
        "domain": request.domain,
        "count": len(subdomains),
        "subdomains": [
            {"subdomain": s.subdomain, "source": s.source, "resolved": s.resolved}
            for s in subdomains
        ],
    }


@router.post("/ports")
async def port_scan(request: PortScanRequest):
    """Scan ports."""
    from nigpig.recon.ports import PortScanner

    scanner = PortScanner(request.host)

    if request.ports:
        results = await scanner.scan_ports(request.ports)
    else:
        results = await scanner.scan_top_ports()

    return {
        "host": request.host,
        "count": len(results),
        "ports": [
            {"port": p.port, "state": p.state, "service": p.service, "banner": p.banner}
            for p in results
        ],
    }


@router.post("/dns")
async def dns_lookup(request: SubdomainRequest):
    """DNS record lookup."""
    from nigpig.recon.dns import DNSResolver

    resolver = DNSResolver()
    records = await resolver.enumerate_all(request.domain)

    return {
        "domain": request.domain,
        "records": {
            rtype: [{"value": r.value, "ttl": r.ttl} for r in recs]
            for rtype, recs in records.items()
        },
    }
