"""Report generation - JSON, Markdown, and HTML formats."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, BaseLoader

from nigpig.reporting.remediation import get_remediation_guidance, map_to_owasp


async def generate_reports(
    findings: list[dict[str, Any]],
    run_info: dict[str, Any],
    output_dir: Path,
) -> None:
    """Generate all report formats.

    Args:
        findings: List of findings.
        run_info: Run metadata.
        output_dir: Output directory.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Enrich findings with remediation
    enriched_findings = []
    for finding in findings:
        enriched = finding.copy()
        enriched["remediation_guidance"] = get_remediation_guidance(finding)
        enriched["owasp_mapping"] = map_to_owasp(finding)
        enriched_findings.append(enriched)

    # Generate severity summary
    severity_summary = {
        "critical": sum(1 for f in enriched_findings if f.get("severity") == "critical"),
        "high": sum(1 for f in enriched_findings if f.get("severity") == "high"),
        "medium": sum(1 for f in enriched_findings if f.get("severity") == "medium"),
        "low": sum(1 for f in enriched_findings if f.get("severity") == "low"),
        "info": sum(1 for f in enriched_findings if f.get("severity") == "info"),
    }

    report_data = {
        "run_info": run_info,
        "findings": enriched_findings,
        "severity_summary": severity_summary,
        "generated_at": datetime.now().isoformat(),
        "total_findings": len(enriched_findings),
    }

    # Generate JSON report
    json_path = output_dir / "report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    # Generate Markdown report
    md_path = output_dir / "report.md"
    md_content = generate_markdown_report(report_data)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    # Generate HTML report
    html_path = output_dir / "report.html"
    html_content = generate_html_report(report_data)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)


def generate_markdown_report(data: dict[str, Any]) -> str:
    """Generate Markdown formatted report.

    Args:
        data: Report data.

    Returns:
        Markdown string.
    """
    run_info = data["run_info"]
    findings = data["findings"]
    summary = data["severity_summary"]

    lines = [
        f"# NigPig Security Scan Report",
        "",
        f"**Target:** {run_info.get('target', 'N/A')}",
        f"**Run ID:** {run_info.get('run_id', 'N/A')}",
        f"**Started:** {run_info.get('start_time', 'N/A')}",
        f"**Completed:** {run_info.get('end_time', 'N/A')}",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| 🔴 Critical | {summary.get('critical', 0)} |",
        f"| 🟠 High | {summary.get('high', 0)} |",
        f"| 🟡 Medium | {summary.get('medium', 0)} |",
        f"| 🔵 Low | {summary.get('low', 0)} |",
        f"| ⚪ Info | {summary.get('info', 0)} |",
        f"| **Total** | **{data['total_findings']}** |",
        "",
        "---",
        "",
        "## Findings",
        "",
    ]

    # Group by severity
    severity_order = ["critical", "high", "medium", "low", "info"]

    for severity in severity_order:
        severity_findings = [f for f in findings if f.get("severity") == severity]
        if not severity_findings:
            continue

        emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(
            severity, "⚪"
        )
        lines.append(f"### {emoji} {severity.upper()} ({len(severity_findings)})")
        lines.append("")

        for i, finding in enumerate(severity_findings, 1):
            lines.append(f"#### {i}. {finding.get('name', 'Unknown')}")
            lines.append("")

            if finding.get("description"):
                lines.append(f"**Description:** {finding['description']}")
                lines.append("")

            if finding.get("url"):
                lines.append(f"**URL:** `{finding['url']}`")
                lines.append("")

            if finding.get("param"):
                lines.append(f"**Parameter:** `{finding['param']}`")
                lines.append("")

            if finding.get("owasp_mapping"):
                lines.append(f"**OWASP Category:** {finding['owasp_mapping']}")
                lines.append("")

            if finding.get("remediation_guidance"):
                lines.append("**Remediation:**")
                lines.append(f"> {finding['remediation_guidance']}")
                lines.append("")

            lines.append("---")
            lines.append("")

    lines.extend(
        [
            "",
            "---",
            "",
            f"*Report generated by NigPig Tools at {data['generated_at']}*",
        ]
    )

    return "\n".join(lines)


def generate_html_report(data: dict[str, Any]) -> str:
    """Generate HTML formatted report.

    Args:
        data: Report data.

    Returns:
        HTML string.
    """
    run_info = data["run_info"]
    findings = data["findings"]
    summary = data["severity_summary"]

    # Group findings by severity
    grouped_findings = {}
    for severity in ["critical", "high", "medium", "low", "info"]:
        grouped_findings[severity] = [f for f in findings if f.get("severity") == severity]

    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NigPig Security Report - {{ run_info.target }}</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #0d6efd;
            --info: #6c757d;
        }
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        .meta {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .meta p { margin: 5px 0; }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 30px 0;
        }
        .summary-card {
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
        }
        .summary-card.critical { background: var(--critical); }
        .summary-card.high { background: var(--high); }
        .summary-card.medium { background: var(--medium); color: #333; }
        .summary-card.low { background: var(--low); }
        .summary-card.info { background: var(--info); }
        .summary-card .count {
            font-size: 2.5em;
            font-weight: bold;
        }
        .summary-card .label {
            font-size: 0.9em;
            text-transform: uppercase;
        }
        .severity-section {
            margin: 30px 0;
        }
        .severity-header {
            padding: 10px 15px;
            border-radius: 5px;
            color: white;
            margin-bottom: 15px;
        }
        .severity-header.critical { background: var(--critical); }
        .severity-header.high { background: var(--high); }
        .severity-header.medium { background: var(--medium); color: #333; }
        .severity-header.low { background: var(--low); }
        .severity-header.info { background: var(--info); }
        .finding {
            background: #f8f9fa;
            border-left: 4px solid #ddd;
            padding: 15px;
            margin: 10px 0;
            border-radius: 0 5px 5px 0;
        }
        .finding.critical { border-left-color: var(--critical); }
        .finding.high { border-left-color: var(--high); }
        .finding.medium { border-left-color: var(--medium); }
        .finding.low { border-left-color: var(--low); }
        .finding.info { border-left-color: var(--info); }
        .finding h4 { margin-top: 0; color: #2c3e50; }
        .finding-meta { font-size: 0.9em; color: #666; }
        .finding-meta code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
        }
        .remediation {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
        }
        .footer {
            text-align: center;
            color: #666;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }
        .collapsible {
            cursor: pointer;
            user-select: none;
        }
        .collapsible:after {
            content: ' ▼';
            font-size: 0.8em;
        }
        .collapsed:after {
            content: ' ▶';
        }
        .content { display: block; }
        .content.hidden { display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐷 NigPig Security Scan Report</h1>
        
        <div class="meta">
            <p><strong>Target:</strong> {{ run_info.target }}</p>
            <p><strong>Run ID:</strong> {{ run_info.run_id }}</p>
            <p><strong>Started:</strong> {{ run_info.start_time }}</p>
            <p><strong>Completed:</strong> {{ run_info.end_time }}</p>
        </div>
        
        <h2>Summary</h2>
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="count">{{ summary.critical }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{{ summary.high }}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{{ summary.medium }}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{{ summary.low }}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">{{ summary.info }}</div>
                <div class="label">Info</div>
            </div>
        </div>
        
        <h2>Findings</h2>
        
        {% for severity in ['critical', 'high', 'medium', 'low', 'info'] %}
        {% if grouped_findings[severity] %}
        <div class="severity-section">
            <h3 class="severity-header {{ severity }} collapsible" onclick="toggleSection(this)">
                {{ severity|upper }} ({{ grouped_findings[severity]|length }})
            </h3>
            <div class="content">
            {% for finding in grouped_findings[severity] %}
                <div class="finding {{ severity }}">
                    <h4>{{ finding.name }}</h4>
                    {% if finding.description %}
                    <p>{{ finding.description }}</p>
                    {% endif %}
                    <div class="finding-meta">
                        {% if finding.url %}
                        <p><strong>URL:</strong> <code>{{ finding.url }}</code></p>
                        {% endif %}
                        {% if finding.param %}
                        <p><strong>Parameter:</strong> <code>{{ finding.param }}</code></p>
                        {% endif %}
                        {% if finding.owasp_mapping %}
                        <p><strong>OWASP:</strong> {{ finding.owasp_mapping }}</p>
                        {% endif %}
                    </div>
                    {% if finding.remediation_guidance %}
                    <div class="remediation">
                        <strong>Remediation:</strong> {{ finding.remediation_guidance }}
                    </div>
                    {% endif %}
                </div>
            {% endfor %}
            </div>
        </div>
        {% endif %}
        {% endfor %}
        
        <div class="footer">
            <p>Report generated by NigPig Tools at {{ generated_at }}</p>
        </div>
    </div>
    
    <script>
        function toggleSection(header) {
            header.classList.toggle('collapsed');
            const content = header.nextElementSibling;
            content.classList.toggle('hidden');
        }
    </script>
</body>
</html>"""

    # Simple template rendering
    env = Environment(loader=BaseLoader())
    template = env.from_string(html_template)

    return template.render(
        run_info=run_info,
        summary=summary,
        grouped_findings=grouped_findings,
        generated_at=data["generated_at"],
    )
