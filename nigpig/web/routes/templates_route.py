"""Templates API routes - vulnerability scanning."""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class TemplateRequest(BaseModel):
    url: str
    tags: list[str] | None = None
    severity: list[str] | None = None


@router.post("/run")
async def run_templates(request: TemplateRequest):
    """Run vulnerability templates."""
    from nigpig.templates.executor import TemplateExecutor
    from nigpig.templates.loader import get_builtin_templates

    templates = get_builtin_templates()

    # Filter by tags if specified
    if request.tags:
        templates = [t for t in templates if any(tag in t.tags for tag in request.tags)]

    # Filter by severity if specified
    if request.severity:
        templates = [
            t for t in templates if t.severity.lower() in [s.lower() for s in request.severity]
        ]

    executor = TemplateExecutor()
    results = await executor.run_templates(templates, request.url)

    return {
        "url": request.url,
        "templates_run": len(templates),
        "findings_count": len(results),
        "findings": [
            {
                "template_id": r.template_id,
                "name": r.template_name,
                "severity": r.severity,
                "url": r.url,
                "evidence": r.evidence,
            }
            for r in results
        ],
    }


@router.get("/list")
async def list_templates():
    """List available templates."""
    from nigpig.templates.loader import get_builtin_templates

    templates = get_builtin_templates()

    return {
        "count": len(templates),
        "templates": [
            {
                "id": t.id,
                "name": t.name,
                "severity": t.severity,
                "tags": t.tags,
                "description": t.description,
            }
            for t in templates
        ],
    }
