"""NigPig CLI - Typer-based command line interface with advanced modules."""

import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from nigpig import __version__, SAFETY_NOTICE
from nigpig.config import load_config, get_profile

app = typer.Typer(
    name="nigpig",
    help="NigPig Tools - Security Testing Automation",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

# Available modules
AVAILABLE_MODULES = [
    "subdomain",
    "ports",
    "fuzz",
    "tech",
    "waf",
    "js",
    "templates",
    "secrets",
    "ssl",
    "screenshot",
    "all",
]


def show_banner() -> None:
    """Display the NigPig banner."""
    banner = """
    ███╗   ██╗██╗ ██████╗ ██████╗ ██╗ ██████╗ 
    ████╗  ██║██║██╔════╝ ██╔══██╗██║██╔════╝ 
    ██╔██╗ ██║██║██║  ███╗██████╔╝██║██║  ███╗
    ██║╚██╗██║██║██║   ██║██╔═══╝ ██║██║   ██║
    ██║ ╚████║██║╚██████╔╝██║     ██║╚██████╔╝
    ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝     ╚═╝ ╚═════╝ 
    """
    console.print(
        Panel(banner, title=f"[bold cyan]NigPig Tools v{__version__}[/]", border_style="cyan")
    )


@app.command(hidden=True)  # Hidden comprehensive scan command
def goldencarrot(
    target: Annotated[str, typer.Option("--target", "-t", help="Target URL/domain to scan")],
    profile: Annotated[str, typer.Option("--profile", "-p", help="Scan profile")] = "balanced",
    modules: Annotated[
        str, typer.Option("--modules", "-m", help="Modules to run (comma-separated)")
    ] = "all",
    cookie: Annotated[str | None, typer.Option("--cookie", "-c", help="Auth cookie")] = None,
    header: Annotated[str | None, typer.Option("--header", "-H", help="Custom header")] = None,
    ignore_robots: Annotated[
        bool, typer.Option("--ignore-robots", help="Ignore robots.txt")
    ] = False,
    timeout: Annotated[int, typer.Option("--timeout", help="Scan timeout in minutes")] = 60,
    output_dir: Annotated[str, typer.Option("--output", "-o", help="Output directory")] = "reports",
    config_file: Annotated[Path | None, typer.Option("--config", help="Custom config file")] = None,
) -> None:
    """
    🥕 GOLDEN CARROT - Full comprehensive security scan.

    Runs all enabled modules including: subdomain enumeration, port scanning,
    content fuzzing, technology fingerprinting, WAF detection, JS analysis,
    vulnerability templates, secret scanning, SSL analysis, and screenshots.
    """
    import asyncio

    show_banner()
    console.print(SAFETY_NOTICE)

    # Parse modules
    selected_modules = [m.strip().lower() for m in modules.split(",")]
    if "all" in selected_modules:
        selected_modules = AVAILABLE_MODULES[:-1]  # All except "all"

    for mod in selected_modules:
        if mod not in AVAILABLE_MODULES:
            console.print(f"[red]Error:[/] Unknown module '{mod}'")
            console.print(f"Available: {', '.join(AVAILABLE_MODULES)}")
            raise typer.Exit(1)

    # Validate profile
    valid_profiles = ["safe", "balanced", "deep"]
    if profile not in valid_profiles:
        console.print(
            f"[red]Error:[/] Invalid profile '{profile}'. Must be one of: {', '.join(valid_profiles)}"
        )
        raise typer.Exit(1)

    # Load configuration
    try:
        config = load_config(config_file)
        profile_config = get_profile(config, profile)
    except Exception as e:
        console.print(f"[red]Error loading config:[/] {e}")
        raise typer.Exit(1)

    # Normalize target URL
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    console.print(f"\n[bold]Target:[/] {target}")
    console.print(f"[bold]Profile:[/] {profile}")
    console.print(f"[bold]Modules:[/] {', '.join(selected_modules)}")
    console.print(f"[bold]Timeout:[/] {timeout} minutes")

    # Create run ID
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    console.print(f"[bold]Run ID:[/] {run_id}\n")

    # Run the scan
    try:
        asyncio.run(
            _run_full_scan(
                target=target,
                run_id=run_id,
                profile=profile,
                profile_config=profile_config,
                config=config,
                modules=selected_modules,
                cookie=cookie,
                header=header,
                ignore_robots=ignore_robots,
                timeout=timeout,
                output_dir=output_dir,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(f"\n[red]Scan failed:[/] {e}")
        raise typer.Exit(1)


@app.command(hidden=True)  # Quick scan command
def carrot(
    target: Annotated[str, typer.Option("--target", "-t", help="Target URL to scan")],
    modules: Annotated[
        str, typer.Option("--modules", "-m", help="Modules to run")
    ] = "tech,templates,ssl",
) -> None:
    """
    🥕 CARROT - Quick lightweight scan.

    Runs a fast scan with selected modules only.
    Default: tech detection, vulnerability templates, SSL check.
    """
    import asyncio

    show_banner()

    selected_modules = [m.strip().lower() for m in modules.split(",")]

    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    console.print(f"\n[bold]Quick Scan:[/] {target}")
    console.print(f"[bold]Modules:[/] {', '.join(selected_modules)}\n")

    try:
        asyncio.run(_run_quick_scan(target, selected_modules))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted.[/]")
        raise typer.Exit(130)
    except Exception as e:
        console.print(f"\n[red]Error:[/] {e}")
        raise typer.Exit(1)


async def _run_quick_scan(target: str, modules: list[str]) -> None:
    """Run a quick scan with selected modules."""

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Tech detection
        if "tech" in modules:
            task = progress.add_task("[cyan]Running technology detection...", total=None)
            from nigpig.fingerprint.tech_detect import TechDetector

            detector = TechDetector()
            techs = await detector.detect(target)
            progress.update(task, description=f"[green]✓ Found {len(techs)} technologies")

            if techs:
                table = Table(title="Technologies Detected")
                table.add_column("Name", style="cyan")
                table.add_column("Category")
                table.add_column("Version")
                for t in techs:
                    table.add_row(t.name, t.category, t.version or "-")
                console.print(table)

        # WAF detection
        if "waf" in modules:
            task = progress.add_task("[cyan]Detecting WAF...", total=None)
            from nigpig.fingerprint.waf_detect import WAFDetector

            detector = WAFDetector()
            wafs = await detector.detect(target)
            if wafs:
                progress.update(task, description=f"[yellow]⚠ WAF detected: {wafs[0].name}")
            else:
                progress.update(task, description="[green]✓ No WAF detected")

        # SSL check
        if "ssl" in modules:
            task = progress.add_task("[cyan]Analyzing SSL/TLS...", total=None)
            from nigpig.audit.ssl import SSLAnalyzer

            analyzer = SSLAnalyzer()
            result = await analyzer.analyze_async(target)
            progress.update(task, description=f"[green]✓ SSL Grade: {result.score}")

            if result.issues:
                console.print("\n[yellow]SSL Issues:[/]")
                for issue in result.issues:
                    console.print(f"  • {issue}")

        # Templates
        if "templates" in modules:
            task = progress.add_task("[cyan]Running vulnerability templates...", total=None)
            from nigpig.templates.executor import TemplateExecutor

            executor = TemplateExecutor()
            results = await executor.run_all_builtin(target)

            if results:
                progress.update(task, description=f"[red]! Found {len(results)} issues")
                for r in results:
                    severity_color = {
                        "critical": "red",
                        "high": "orange1",
                        "medium": "yellow",
                        "low": "blue",
                    }.get(r.severity, "dim")
                    console.print(
                        f"  [{severity_color}][{r.severity.upper()}][/] {r.template_name} - {r.url}"
                    )
            else:
                progress.update(task, description="[green]✓ No vulnerabilities from templates")

    console.print("\n[bold green]Quick scan complete![/]")


async def _run_full_scan(
    target: str,
    run_id: str,
    profile: str,
    profile_config: dict,
    config: dict,
    modules: list[str],
    cookie: str | None,
    header: str | None,
    ignore_robots: bool,
    timeout: int,
    output_dir: str,
) -> None:
    """Execute the full scan pipeline with all modules."""
    from urllib.parse import urlparse

    parsed = urlparse(target)
    domain = parsed.netloc.split(":")[0]

    results = {
        "target": target,
        "domain": domain,
        "run_id": run_id,
        "profile": profile,
        "modules": modules,
        "findings": [],
    }

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Subdomain enumeration
        if "subdomain" in modules:
            task = progress.add_task("[cyan]Enumerating subdomains...", total=None)
            from nigpig.recon.subdomain import SubdomainEnumerator

            enumerator = SubdomainEnumerator(domain)
            subdomains = await enumerator.enumerate_all()
            results["subdomains"] = [s.subdomain for s in subdomains]
            progress.update(task, description=f"[green]✓ Found {len(subdomains)} subdomains")

        # Port scanning
        if "ports" in modules:
            task = progress.add_task("[cyan]Scanning ports...", total=None)
            from nigpig.recon.ports import PortScanner

            scanner = PortScanner(domain)
            ports = await scanner.scan_top_ports()
            results["open_ports"] = [{"port": p.port, "service": p.service} for p in ports]
            progress.update(task, description=f"[green]✓ Found {len(ports)} open ports")

        # Technology detection
        if "tech" in modules:
            task = progress.add_task("[cyan]Detecting technologies...", total=None)
            from nigpig.fingerprint.tech_detect import TechDetector

            detector = TechDetector()
            techs = await detector.detect(target)
            results["technologies"] = [
                {"name": t.name, "category": t.category, "version": t.version} for t in techs
            ]
            progress.update(task, description=f"[green]✓ Found {len(techs)} technologies")

        # WAF detection
        if "waf" in modules:
            task = progress.add_task("[cyan]Detecting WAF...", total=None)
            from nigpig.fingerprint.waf_detect import WAFDetector

            detector = WAFDetector()
            wafs = await detector.detect(target)
            results["waf"] = wafs[0].name if wafs else None
            progress.update(task, description=f"[green]✓ WAF: {wafs[0].name if wafs else 'None'}")

        # Content fuzzing
        if "fuzz" in modules:
            task = progress.add_task("[cyan]Fuzzing content...", total=None)
            from nigpig.discovery.fuzzer import ContentFuzzer

            fuzzer = ContentFuzzer(target, rate_limit=10.0)
            fuzz_results = await fuzzer.fuzz_default()
            results["discovered_paths"] = [r.url for r in fuzz_results]
            progress.update(task, description=f"[green]✓ Found {len(fuzz_results)} paths")

        # JavaScript analysis
        if "js" in modules:
            task = progress.add_task("[cyan]Analyzing JavaScript...", total=None)
            from nigpig.discovery.js_analyzer import JSAnalyzer, find_js_files

            js_files = await find_js_files(target)
            analyzer = JSAnalyzer(target)
            all_endpoints = []
            all_secrets = []
            for js_url in js_files[:10]:  # Limit to 10 files
                endpoints, secrets = await analyzer.analyze_url(js_url)
                all_endpoints.extend(endpoints)
                all_secrets.extend(secrets)
            results["js_endpoints"] = len(all_endpoints)
            results["js_secrets"] = len(all_secrets)
            progress.update(
                task,
                description=f"[green]✓ JS: {len(all_endpoints)} endpoints, {len(all_secrets)} secrets",
            )

            if all_secrets:
                for s in all_secrets:
                    results["findings"].append(
                        {
                            "type": "js_secret",
                            "severity": "high",
                            "name": s.type,
                            "url": s.source_file,
                        }
                    )

        # Vulnerability templates
        if "templates" in modules:
            task = progress.add_task("[cyan]Running vulnerability templates...", total=None)
            from nigpig.templates.executor import TemplateExecutor

            executor = TemplateExecutor()
            template_results = await executor.run_all_builtin(target)
            for r in template_results:
                results["findings"].append(
                    {
                        "type": "template",
                        "severity": r.severity,
                        "name": r.template_name,
                        "url": r.url,
                    }
                )
            progress.update(
                task, description=f"[green]✓ Templates: {len(template_results)} findings"
            )

        # SSL analysis
        if "ssl" in modules:
            task = progress.add_task("[cyan]Analyzing SSL/TLS...", total=None)
            from nigpig.audit.ssl import SSLAnalyzer

            analyzer = SSLAnalyzer()
            ssl_result = await analyzer.analyze_async(target)
            results["ssl"] = {
                "grade": ssl_result.score,
                "protocol": ssl_result.protocol,
                "issues": ssl_result.issues,
            }
            for issue in ssl_result.issues:
                results["findings"].append(
                    {
                        "type": "ssl",
                        "severity": "medium",
                        "name": issue,
                        "url": target,
                    }
                )
            progress.update(task, description=f"[green]✓ SSL Grade: {ssl_result.score}")

        # Screenshots
        if "screenshot" in modules:
            task = progress.add_task("[cyan]Capturing screenshots...", total=None)
            try:
                from nigpig.visual.screenshot import ScreenshotTaker

                screenshot_dir = Path(output_dir) / run_id / "screenshots"
                screenshot_dir.mkdir(parents=True, exist_ok=True)
                async with ScreenshotTaker(output_dir=screenshot_dir) as taker:
                    ss_result = await taker.capture(target)
                    results["screenshot"] = ss_result.file_path
                progress.update(task, description="[green]✓ Screenshot captured")
            except ImportError:
                progress.update(task, description="[yellow]⚠ Playwright not installed")

    # Display summary
    _display_full_summary(results, output_dir, run_id)

    # Save results
    import json

    output_path = Path(output_dir) / run_id
    output_path.mkdir(parents=True, exist_ok=True)
    with open(output_path / "results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    console.print(f"\n[bold]Results saved to:[/] {output_path.absolute()}")


def _display_full_summary(results: dict, output_dir: str, run_id: str) -> None:
    """Display full scan summary."""
    console.print("\n" + "=" * 60)
    console.print("[bold cyan]Scan Complete[/]")
    console.print("=" * 60)

    # Summary table
    summary = Table(title="Scan Summary")
    summary.add_column("Category", style="cyan")
    summary.add_column("Count", justify="right")

    if "subdomains" in results:
        summary.add_row("Subdomains", str(len(results["subdomains"])))
    if "open_ports" in results:
        summary.add_row("Open Ports", str(len(results["open_ports"])))
    if "technologies" in results:
        summary.add_row("Technologies", str(len(results["technologies"])))
    if "discovered_paths" in results:
        summary.add_row("Discovered Paths", str(len(results["discovered_paths"])))
    if "js_endpoints" in results:
        summary.add_row("JS Endpoints", str(results["js_endpoints"]))

    total_findings = len(results.get("findings", []))
    summary.add_row("[bold]Total Findings[/]", f"[bold]{total_findings}[/]")

    console.print(summary)

    # Findings by severity
    if results.get("findings"):
        findings_table = Table(title="Findings by Severity")
        findings_table.add_column("Severity", style="bold")
        findings_table.add_column("Count", justify="right")

        by_severity = {}
        for f in results["findings"]:
            sev = f.get("severity", "info")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        severity_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(sev, 0)
            if count > 0:
                findings_table.add_row(f"[{severity_colors[sev]}]{sev.upper()}[/]", str(count))

        console.print(findings_table)


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"NigPig Tools v{__version__}")


@app.command()
def doctor() -> None:
    """Check system requirements and dependencies."""
    import subprocess
    import shutil

    show_banner()
    console.print("\n[bold]Checking system requirements...[/]\n")

    checks = []

    # Check Python version
    py_version = sys.version_info
    py_ok = py_version >= (3, 11)
    checks.append(
        ("Python 3.11+", py_ok, f"{py_version.major}.{py_version.minor}.{py_version.micro}")
    )

    # Check Docker
    docker_path = shutil.which("docker")
    docker_ok = docker_path is not None
    checks.append(("Docker", docker_ok, docker_path or "Not found"))

    # Check if ZAP container is running
    zap_ok = False
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=nigpig-zap", "--format", "{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        zap_ok = "Up" in result.stdout
        zap_status = result.stdout.strip() if zap_ok else "Not running"
    except Exception:
        zap_status = "Could not check"
    checks.append(("ZAP Container", zap_ok, zap_status))

    # Check dnspython
    try:
        import dns.resolver

        dns_ok = True
        dns_status = "Installed"
    except ImportError:
        dns_ok = False
        dns_status = "Not installed"
    checks.append(("dnspython", dns_ok, dns_status))

    # Check Playwright
    try:
        from playwright.async_api import async_playwright

        pw_ok = True
        pw_status = "Installed"
    except ImportError:
        pw_ok = False
        pw_status = "pip install playwright && playwright install chromium"
    checks.append(("Playwright (optional)", pw_ok, pw_status))

    # Display results
    table = Table(title="System Check Results")
    table.add_column("Component", style="cyan")
    table.add_column("Status")
    table.add_column("Details")

    for name, ok, details in checks:
        status = "[green]✓[/]" if ok else "[red]✗[/]"
        table.add_row(name, status, details)

    console.print(table)

    if not all(ok for _, ok, _ in checks[:3]):  # First 3 are required
        console.print("\n[yellow]Some required checks failed. Run the following to fix:[/]")
        if not docker_ok:
            console.print("  • Install Docker: https://docs.docker.com/get-docker/")
        if not zap_ok and docker_ok:
            console.print("  • Start ZAP: docker-compose up -d zap")


@app.command()
def modules() -> None:
    """List available scan modules."""
    show_banner()

    table = Table(title="Available Modules")
    table.add_column("Module", style="cyan")
    table.add_column("Description")

    module_desc = {
        "subdomain": "Subdomain enumeration (CT logs, brute-force)",
        "ports": "TCP port scanning with service detection",
        "fuzz": "Content/directory fuzzing with wordlists",
        "tech": "Technology fingerprinting (Wappalyzer-style)",
        "waf": "WAF detection and identification",
        "js": "JavaScript analysis (endpoints, secrets)",
        "templates": "Nuclei-style vulnerability templates",
        "secrets": "Secret/credential detection",
        "ssl": "SSL/TLS configuration analysis",
        "screenshot": "Capture page screenshots (requires Playwright)",
        "all": "Run all modules",
    }

    for mod, desc in module_desc.items():
        table.add_row(mod, desc)

    console.print(table)
    console.print("\n[bold]Usage:[/]")
    console.print("  nigpig goldencarrot -t example.com -m subdomain,ports,tech")
    console.print("  nigpig goldencarrot -t example.com -m all")
    console.print("  nigpig carrot -t example.com -m tech,ssl")


@app.command()
def gui() -> None:
    """🖥️ Launch the desktop GUI application."""
    show_banner()
    console.print("\n[bold green]Launching Desktop Application...[/]")

    from nigpig.gui.app import main

    main()


@app.command()
def web(
    host: Annotated[str, typer.Option("--host", "-h", help="Host to bind")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", "-p", help="Port to bind")] = 8888,
) -> None:
    """Start the web dashboard server."""
    show_banner()
    console.print(f"\n[bold green]Starting web dashboard...[/]")
    console.print(f"[bold]URL:[/] http://{host}:{port}")
    console.print("[dim]Press Ctrl+C to stop[/]\n")

    from nigpig.web.app import run_server

    run_server(host=host, port=port)


if __name__ == "__main__":
    app()
