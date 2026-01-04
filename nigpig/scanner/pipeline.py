"""Main scan pipeline orchestration."""

import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from nigpig.scanner.zap_client import ZAPClient, ZAPClientError
from nigpig.scanner.passive_checks import run_all_passive_checks, CheckResult
from nigpig.discovery.sitemap import fetch_sitemap_urls
from nigpig.discovery.robots import parse_robots_txt
from nigpig.discovery.url_utils import normalize_url, deduplicate_urls, is_same_origin
from nigpig.storage.db import Database
from nigpig.storage.masking import mask_sensitive_data
from nigpig.reporting.generator import generate_reports
from nigpig.safety.scope import ScopeValidator


async def run_scan_pipeline(
    target: str,
    run_id: str,
    profile_config: dict[str, Any],
    config: dict[str, Any],
    db: Database,
    scope_validator: ScopeValidator,
    cookie: Optional[str] = None,
    header: Optional[str] = None,
    timeout: int = 30,
    console: Optional[Console] = None,
) -> dict[str, Any]:
    """Run the complete scan pipeline.

    Args:
        target: Target URL.
        run_id: Unique run identifier.
        profile_config: Profile-specific configuration.
        config: Full configuration.
        db: Database instance.
        scope_validator: Scope validator.
        cookie: Optional auth cookie.
        header: Optional custom header.
        timeout: Timeout in minutes.
        console: Rich console for output.

    Returns:
        Results summary dictionary.
    """
    console = console or Console()
    start_time = datetime.now()
    end_time = start_time + timedelta(minutes=timeout)

    results = {
        "total_urls": 0,
        "unique_endpoints": 0,
        "scanned_urls": 0,
        "findings_by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        },
        "findings": [],
    }

    zap_config = config.get("zap", {})

    async with ZAPClient(
        host=zap_config.get("host", "localhost"),
        port=zap_config.get("port", 8080),
        api_key=zap_config.get("api_key", ""),
    ) as zap:
        try:
            # Step 1: Initialize ZAP session
            console.print("[cyan]Step 1/6:[/] Initializing ZAP session...")
            await zap.new_session(f"nigpig_{run_id}")
            version = await zap.get_version()
            console.print(f"  ✓ Connected to ZAP {version}")

            # Set authentication if provided
            if cookie or header:
                console.print("  ✓ Authentication configured")

            # Step 2: Discovery
            console.print("\n[cyan]Step 2/6:[/] URL Discovery...")
            discovered_urls = await _run_discovery(
                zap=zap,
                target=target,
                profile_config=profile_config,
                config=config,
                scope_validator=scope_validator,
                console=console,
                end_time=end_time,
            )

            results["total_urls"] = len(discovered_urls)
            unique_urls = deduplicate_urls(discovered_urls)
            results["unique_endpoints"] = len(unique_urls)

            console.print(f"  ✓ Found {len(discovered_urls)} URLs ({len(unique_urls)} unique)")

            # Save URLs to database
            for url in unique_urls:
                await db.save_url(run_id, url)

            # Step 3: Passive Analysis
            console.print("\n[cyan]Step 3/6:[/] Passive Security Analysis...")
            passive_findings = await _run_passive_analysis(
                target=target,
                console=console,
            )

            for finding in passive_findings:
                if not finding.passed:
                    results["findings"].append(_check_to_finding(finding))
                    results["findings_by_severity"][finding.severity] += 1

            console.print(f"  ✓ Passive checks complete ({len(passive_findings)} checks)")

            # Wait for ZAP passive scan
            console.print("  • Waiting for ZAP passive scan...")
            await zap.wait_for_passive_scan()
            console.print("  ✓ ZAP passive scan complete")

            # Step 4: Active Scan (if enabled and time permits)
            if profile_config.get("active_scan_enabled", False) and datetime.now() < end_time:
                console.print("\n[cyan]Step 4/6:[/] Controlled Active Scan...")
                await _run_active_scan(
                    zap=zap,
                    target=target,
                    profile_config=profile_config,
                    console=console,
                    end_time=end_time,
                )
            else:
                console.print("\n[cyan]Step 4/6:[/] Active scan skipped (profile or timeout)")

            # Step 5: Collect findings from ZAP
            console.print("\n[cyan]Step 5/6:[/] Collecting findings...")
            zap_alerts = await zap.get_alerts(base_url=target)

            for alert in zap_alerts:
                finding = _zap_alert_to_finding(alert)
                results["findings"].append(finding)
                severity = _risk_to_severity(alert.get("risk", "0"))
                results["findings_by_severity"][severity] += 1

            console.print(f"  ✓ Collected {len(zap_alerts)} ZAP findings")
            results["scanned_urls"] = len(unique_urls)

        except ZAPClientError as e:
            console.print(f"\n[red]ZAP Error:[/] {e}")
            console.print("[yellow]Continuing with passive-only results...[/]")

        # Step 6: Generate reports
        console.print("\n[cyan]Step 6/6:[/] Generating reports...")

        # Save findings to database
        for finding in results["findings"]:
            masked_finding = mask_sensitive_data(finding)
            await db.save_finding(run_id, masked_finding)

        # Generate report files
        report_dir = Path("reports") / run_id
        report_dir.mkdir(parents=True, exist_ok=True)

        await generate_reports(
            findings=results["findings"],
            run_info={
                "run_id": run_id,
                "target": target,
                "profile": profile_config,
                "start_time": start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "total_urls": results["total_urls"],
                "unique_endpoints": results["unique_endpoints"],
            },
            output_dir=report_dir,
        )

        console.print(f"  ✓ Reports saved to {report_dir}")

        # Update run status in database
        await db.update_run_status(run_id, "completed", results)

    return results


async def _run_discovery(
    zap: ZAPClient,
    target: str,
    profile_config: dict[str, Any],
    config: dict[str, Any],
    scope_validator: ScopeValidator,
    console: Console,
    end_time: datetime,
) -> list[str]:
    """Run URL discovery phase.

    Returns:
        List of discovered URLs.
    """
    discovered: list[str] = [target]

    # Seed ZAP with target
    await zap.access_url(target)

    # Fetch sitemap
    if config.get("discovery", {}).get("parse_sitemap", True):
        console.print("  • Fetching sitemap...")
        sitemap_urls = await fetch_sitemap_urls(target)
        # Filter by scope
        sitemap_urls = [u for u in sitemap_urls if scope_validator.is_in_scope(u)]
        discovered.extend(sitemap_urls)
        console.print(f"    Found {len(sitemap_urls)} URLs from sitemap")

    # Run ZAP spider
    spider_max_depth = profile_config.get("spider_max_depth", 5)
    spider_max_duration = profile_config.get("spider_max_duration", 10)

    console.print(f"  • Running spider (depth={spider_max_depth}, max {spider_max_duration}min)...")
    scan_id = await zap.start_spider(
        url=target,
        max_depth=spider_max_depth,
        max_duration=spider_max_duration,
    )

    # Wait with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("    Spider progress", total=100)

        while True:
            if datetime.now() >= end_time:
                console.print("    [yellow]Timeout reached, stopping spider[/]")
                break

            status = await zap.get_spider_status(scan_id)
            progress.update(task, completed=status)

            if status >= 100:
                break
            await asyncio.sleep(2)

    spider_urls = await zap.get_spider_results(scan_id)
    spider_urls = [u for u in spider_urls if scope_validator.is_in_scope(u)]
    discovered.extend(spider_urls)
    console.print(f"    Found {len(spider_urls)} URLs from spider")

    # Run AJAX spider if enabled
    if profile_config.get("ajax_spider_enabled", False) and datetime.now() < end_time:
        ajax_max_duration = profile_config.get("ajax_spider_max_duration", 5)
        console.print(f"  • Running AJAX spider (max {ajax_max_duration}min)...")

        await zap.start_ajax_spider(target, max_duration=ajax_max_duration)

        # Wait for AJAX spider
        while await zap.get_ajax_spider_status() == "running":
            if datetime.now() >= end_time:
                console.print("    [yellow]Timeout reached[/]")
                break
            await asyncio.sleep(2)

        console.print("    ✓ AJAX spider complete")

    return discovered


async def _run_passive_analysis(
    target: str,
    console: Console,
) -> list[CheckResult]:
    """Run passive security analysis.

    Returns:
        List of check results.
    """
    console.print("  • Checking security headers...")
    results = await run_all_passive_checks(target)

    failed_count = sum(1 for r in results if not r.passed)
    console.print(f"    Found {failed_count} issues in passive checks")

    return results


async def _run_active_scan(
    zap: ZAPClient,
    target: str,
    profile_config: dict[str, Any],
    console: Console,
    end_time: datetime,
) -> None:
    """Run controlled active scan."""
    policy = profile_config.get("active_scan_policy", "Light")

    console.print(f"  • Starting active scan (policy={policy})...")
    scan_id = await zap.start_active_scan(target, policy=policy)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("    Active scan progress", total=100)

        while True:
            if datetime.now() >= end_time:
                console.print("\n    [yellow]Timeout reached, stopping active scan[/]")
                await zap.stop_active_scan(scan_id)
                break

            status = await zap.get_active_scan_status(scan_id)
            progress.update(task, completed=status)

            if status >= 100:
                break
            await asyncio.sleep(5)

    console.print("  ✓ Active scan complete")


def _check_to_finding(check: CheckResult) -> dict[str, Any]:
    """Convert CheckResult to finding dictionary."""
    return {
        "source": "passive_check",
        "name": check.check_name,
        "description": check.description,
        "severity": check.severity,
        "details": check.details,
        "remediation": check.remediation,
    }


def _zap_alert_to_finding(alert: dict[str, Any]) -> dict[str, Any]:
    """Convert ZAP alert to finding dictionary."""
    return {
        "source": "zap",
        "name": alert.get("name", "Unknown"),
        "description": alert.get("description", ""),
        "severity": _risk_to_severity(alert.get("risk", "0")),
        "url": alert.get("url", ""),
        "param": alert.get("param", ""),
        "evidence": mask_sensitive_data({"evidence": alert.get("evidence", "")}).get(
            "evidence", ""
        ),
        "solution": alert.get("solution", ""),
        "reference": alert.get("reference", ""),
        "cweid": alert.get("cweid", ""),
        "wascid": alert.get("wascid", ""),
    }


def _risk_to_severity(risk: str) -> str:
    """Convert ZAP risk level to severity string."""
    risk_map = {
        "0": "info",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",  # ZAP doesn't have critical, but for future
    }
    return risk_map.get(str(risk), "info")
