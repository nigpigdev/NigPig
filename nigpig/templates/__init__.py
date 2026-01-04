"""Templates module - Nuclei-style vulnerability scanning."""

from nigpig.templates.loader import TemplateLoader, VulnTemplate
from nigpig.templates.executor import TemplateExecutor, TemplateResult

__all__ = ["TemplateLoader", "VulnTemplate", "TemplateExecutor", "TemplateResult"]
