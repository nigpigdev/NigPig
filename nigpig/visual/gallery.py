"""Gallery generator - create HTML gallery from screenshots."""

from pathlib import Path

from jinja2 import Environment, BaseLoader

from nigpig.visual.screenshot import ScreenshotResult


GALLERY_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NigPig Screenshot Gallery</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            margin: 0;
            padding: 20px;
        }
        h1 {
            text-align: center;
            color: #ff6b6b;
            margin-bottom: 30px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
            gap: 20px;
            max-width: 1800px;
            margin: 0 auto;
        }
        .card {
            background: #16213e;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            transition: transform 0.2s;
        }
        .card:hover {
            transform: translateY(-5px);
        }
        .screenshot {
            width: 100%;
            height: 300px;
            object-fit: cover;
            object-position: top;
            cursor: pointer;
        }
        .info {
            padding: 15px;
        }
        .title {
            font-size: 14px;
            font-weight: bold;
            color: #4ecdc4;
            margin-bottom: 5px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        .url {
            font-size: 12px;
            color: #888;
            word-break: break-all;
        }
        .meta {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
            font-size: 11px;
            color: #666;
        }
        .status {
            padding: 2px 8px;
            border-radius: 10px;
            font-weight: bold;
        }
        .status-200 { background: #2ecc71; color: #fff; }
        .status-301, .status-302 { background: #f39c12; color: #fff; }
        .status-403, .status-404 { background: #e74c3c; color: #fff; }
        .status-500 { background: #9b59b6; color: #fff; }
        .error { color: #e74c3c; font-size: 12px; padding: 10px; }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.9);
            z-index: 1000;
            cursor: pointer;
        }
        .modal img {
            max-width: 95%;
            max-height: 95%;
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
        }
        .modal.active { display: block; }
        .summary {
            text-align: center;
            margin-bottom: 20px;
            color: #888;
        }
    </style>
</head>
<body>
    <h1>🐷 NigPig Screenshot Gallery</h1>
    <div class="summary">
        {{ screenshots|length }} screenshots captured
    </div>
    
    <div class="grid">
        {% for ss in screenshots %}
        <div class="card">
            {% if ss.error %}
            <div class="error">⚠️ {{ ss.error }}</div>
            {% else %}
            <img class="screenshot" src="{{ ss.file_path }}" alt="{{ ss.title }}" onclick="showModal(this.src)">
            {% endif %}
            <div class="info">
                <div class="title">{{ ss.title or 'No title' }}</div>
                <div class="url">{{ ss.url }}</div>
                <div class="meta">
                    <span>{{ ss.width }}x{{ ss.height }}</span>
                    <span class="status status-{{ ss.status_code }}">{{ ss.status_code }}</span>
                </div>
            </div>
        </div>
        {% endfor %}
    </div>
    
    <div class="modal" id="modal" onclick="hideModal()">
        <img id="modal-img" src="">
    </div>
    
    <script>
        function showModal(src) {
            document.getElementById('modal-img').src = src;
            document.getElementById('modal').classList.add('active');
        }
        function hideModal() {
            document.getElementById('modal').classList.remove('active');
        }
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') hideModal();
        });
    </script>
</body>
</html>"""


def generate_gallery(
    screenshots: list[ScreenshotResult],
    output_path: Path | str = "gallery.html",
    title: str = "NigPig Screenshot Gallery",
) -> str:
    """Generate HTML gallery from screenshots.

    Args:
        screenshots: List of screenshot results.
        output_path: Output HTML file path.
        title: Gallery title.

    Returns:
        Path to generated HTML file.
    """
    output_path = Path(output_path)

    # Make file paths relative to gallery location
    gallery_dir = output_path.parent
    processed = []

    for ss in screenshots:
        ss_dict = {
            "url": ss.url,
            "title": ss.title,
            "status_code": ss.status_code,
            "width": ss.width,
            "height": ss.height,
            "error": ss.error,
            "file_path": "",
        }

        if ss.file_path:
            try:
                rel_path = Path(ss.file_path).relative_to(gallery_dir)
                ss_dict["file_path"] = str(rel_path)
            except ValueError:
                ss_dict["file_path"] = ss.file_path

        processed.append(ss_dict)

    # Render template
    env = Environment(loader=BaseLoader())
    template = env.from_string(GALLERY_TEMPLATE)
    html = template.render(screenshots=processed, title=title)

    # Write to file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return str(output_path)


def generate_simple_report(
    screenshots: list[ScreenshotResult],
    output_path: Path | str = "screenshot_report.md",
) -> str:
    """Generate Markdown report from screenshots.

    Args:
        screenshots: List of screenshot results.
        output_path: Output Markdown file path.

    Returns:
        Path to generated file.
    """
    output_path = Path(output_path)

    lines = [
        "# Screenshot Report",
        "",
        f"**Total:** {len(screenshots)} URLs",
        "",
        "| URL | Title | Status | Screenshot |",
        "|-----|-------|--------|------------|",
    ]

    for ss in screenshots:
        title = ss.title[:50] + "..." if len(ss.title) > 50 else ss.title
        if ss.error:
            lines.append(f"| {ss.url} | Error | - | {ss.error} |")
        else:
            rel_path = Path(ss.file_path).name if ss.file_path else ""
            lines.append(f"| {ss.url} | {title} | {ss.status_code} | [{rel_path}]({rel_path}) |")

    content = "\n".join(lines)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)

    return str(output_path)
