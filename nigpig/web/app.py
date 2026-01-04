"""FastAPI application for NigPig Web Dashboard."""

import asyncio
import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sse_starlette.sse import EventSourceResponse

# Store for active scans
active_scans: dict[str, dict[str, Any]] = {}
scan_results: dict[str, dict[str, Any]] = {}


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="NigPig Tools",
        description="Security Testing Automation Dashboard",
        version="2.0.0",
    )

    # Static files
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Include routes
    from nigpig.web.routes import (
        dashboard,
        recon,
        fingerprint,
        templates_route,
        secrets_route,
        audit,
    )

    app.include_router(dashboard.router)
    app.include_router(recon.router, prefix="/api/recon", tags=["Recon"])
    app.include_router(fingerprint.router, prefix="/api/fingerprint", tags=["Fingerprint"])
    app.include_router(templates_route.router, prefix="/api/templates", tags=["Templates"])
    app.include_router(secrets_route.router, prefix="/api/secrets", tags=["Secrets"])
    app.include_router(audit.router, prefix="/api/audit", tags=["Audit"])

    @app.get("/", response_class=HTMLResponse)
    async def index():
        """Serve the main dashboard."""
        html_path = static_dir / "index.html"
        if html_path.exists():
            return HTMLResponse(content=html_path.read_text(encoding="utf-8"))
        return HTMLResponse(content="<h1>NigPig Dashboard</h1><p>Static files not found.</p>")

    @app.get("/api/status")
    async def system_status():
        """Get system status."""
        import shutil
        import subprocess

        docker_ok = shutil.which("docker") is not None
        zap_ok = False

        if docker_ok:
            try:
                result = subprocess.run(
                    ["docker", "ps", "--filter", "name=nigpig-zap", "--format", "{{.Status}}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                zap_ok = "Up" in result.stdout
            except Exception:
                pass

        return {
            "python": True,
            "docker": docker_ok,
            "zap": zap_ok,
            "active_scans": len(active_scans),
        }

    @app.post("/api/scan/start")
    async def start_scan(request: Request, background_tasks: BackgroundTasks):
        """Start a new scan."""
        data = await request.json()
        target = data.get("target", "")
        modules = data.get("modules", ["tech", "templates", "ssl"])

        if not target:
            return JSONResponse({"error": "Target required"}, status_code=400)

        scan_id = str(uuid.uuid4())[:8]
        active_scans[scan_id] = {
            "id": scan_id,
            "target": target,
            "modules": modules,
            "status": "running",
            "progress": 0,
            "started_at": datetime.now().isoformat(),
            "results": {},
        }

        background_tasks.add_task(run_scan_task, scan_id, target, modules)

        return {"scan_id": scan_id, "status": "started"}

    @app.get("/api/scan/{scan_id}")
    async def get_scan_status(scan_id: str):
        """Get scan status."""
        if scan_id in active_scans:
            return active_scans[scan_id]
        if scan_id in scan_results:
            return scan_results[scan_id]
        return JSONResponse({"error": "Scan not found"}, status_code=404)

    @app.get("/api/scan/{scan_id}/stream")
    async def scan_stream(scan_id: str):
        """SSE stream for scan progress."""

        async def event_generator():
            while scan_id in active_scans:
                yield {
                    "event": "progress",
                    "data": json.dumps(active_scans[scan_id]),
                }
                await asyncio.sleep(1)

            if scan_id in scan_results:
                yield {
                    "event": "complete",
                    "data": json.dumps(scan_results[scan_id]),
                }

        return EventSourceResponse(event_generator())

    @app.get("/api/results")
    async def get_all_results():
        """Get all scan results."""
        return list(scan_results.values())

    return app


async def run_scan_task(scan_id: str, target: str, modules: list[str]) -> None:
    """Background task to run scan."""
    from urllib.parse import urlparse

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    domain = parsed.netloc.split(":")[0]

    total_modules = len(modules)
    current = 0

    try:
        # Tech detection
        if "tech" in modules:
            active_scans[scan_id]["current_module"] = "tech"
            active_scans[scan_id]["progress"] = int((current / total_modules) * 100)

            from nigpig.fingerprint.tech_detect import TechDetector

            detector = TechDetector()
            techs = await detector.detect(target)
            active_scans[scan_id]["results"]["technologies"] = [
                {"name": t.name, "category": t.category, "version": t.version} for t in techs
            ]
            current += 1

        # WAF detection
        if "waf" in modules:
            active_scans[scan_id]["current_module"] = "waf"
            active_scans[scan_id]["progress"] = int((current / total_modules) * 100)

            from nigpig.fingerprint.waf_detect import WAFDetector

            detector = WAFDetector()
            wafs = await detector.detect(target)
            active_scans[scan_id]["results"]["waf"] = wafs[0].name if wafs else None
            current += 1

        # Templates
        if "templates" in modules:
            active_scans[scan_id]["current_module"] = "templates"
            active_scans[scan_id]["progress"] = int((current / total_modules) * 100)

            from nigpig.templates.executor import TemplateExecutor

            executor = TemplateExecutor()
            results = await executor.run_all_builtin(target)
            active_scans[scan_id]["results"]["vulnerabilities"] = [
                {"name": r.template_name, "severity": r.severity, "url": r.url} for r in results
            ]
            current += 1

        # SSL
        if "ssl" in modules:
            active_scans[scan_id]["current_module"] = "ssl"
            active_scans[scan_id]["progress"] = int((current / total_modules) * 100)

            from nigpig.audit.ssl import SSLAnalyzer

            analyzer = SSLAnalyzer()
            result = await analyzer.analyze_async(target)
            active_scans[scan_id]["results"]["ssl"] = {
                "grade": result.score,
                "protocol": result.protocol,
                "issues": result.issues,
            }
            current += 1

        # Subdomain
        if "subdomain" in modules:
            active_scans[scan_id]["current_module"] = "subdomain"
            active_scans[scan_id]["progress"] = int((current / total_modules) * 100)

            from nigpig.recon.subdomain import SubdomainEnumerator

            enumerator = SubdomainEnumerator(domain)
            subdomains = await enumerator.enumerate_all()
            active_scans[scan_id]["results"]["subdomains"] = [s.subdomain for s in subdomains[:50]]
            current += 1

        # Ports
        if "ports" in modules:
            active_scans[scan_id]["current_module"] = "ports"
            active_scans[scan_id]["progress"] = int((current / total_modules) * 100)

            from nigpig.recon.ports import PortScanner

            scanner = PortScanner(domain)
            ports = await scanner.scan_top_ports()
            active_scans[scan_id]["results"]["ports"] = [
                {"port": p.port, "service": p.service, "banner": p.banner[:50] if p.banner else ""}
                for p in ports
            ]
            current += 1

        # Fuzz
        if "fuzz" in modules:
            active_scans[scan_id]["current_module"] = "fuzz"
            active_scans[scan_id]["progress"] = int((current / total_modules) * 100)

            from nigpig.discovery.fuzzer import ContentFuzzer

            fuzzer = ContentFuzzer(target, rate_limit=10.0)
            results = await fuzzer.fuzz_default()
            active_scans[scan_id]["results"]["discovered_paths"] = [
                {"url": r.url, "status": r.status_code} for r in results[:50]
            ]
            current += 1

        # Complete
        active_scans[scan_id]["progress"] = 100
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["completed_at"] = datetime.now().isoformat()

        # Move to results
        scan_results[scan_id] = active_scans.pop(scan_id)

    except Exception as e:
        active_scans[scan_id]["status"] = "error"
        active_scans[scan_id]["error"] = str(e)
        scan_results[scan_id] = active_scans.pop(scan_id)


def run_server(host: str = "127.0.0.1", port: int = 8888) -> None:
    """Run the web server."""
    import uvicorn

    app = create_app()
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
