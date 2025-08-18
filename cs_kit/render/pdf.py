"""PDF rendering functionality using Jinja2 templates and WeasyPrint."""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

# WeasyPrint will be imported on-demand to avoid system dependency issues
weasyprint = None
WEASYPRINT_AVAILABLE = None


def _check_weasyprint() -> bool:
    """Check if WeasyPrint is available and can be imported."""
    global weasyprint, WEASYPRINT_AVAILABLE
    
    if WEASYPRINT_AVAILABLE is not None:
        return WEASYPRINT_AVAILABLE
    
    try:
        import weasyprint as wp
        weasyprint = wp
        WEASYPRINT_AVAILABLE = True
        return True
    except (ImportError, OSError) as e:
        # OSError is raised when system dependencies are missing
        weasyprint = None
        WEASYPRINT_AVAILABLE = False
        return False

from cs_kit.cli.config import RendererConfig
from cs_kit.normalizer.ocsf_models import FindingSummary, OCSFEnrichedFinding
from cs_kit.normalizer.summarize import (
    by_framework,
    by_provider,
    framework_score,
    unique_resource_analysis,
)


class RenderError(Exception):
    """Base exception for rendering errors."""

    pass


class TemplateNotFoundError(RenderError):
    """Raised when a template file is not found."""

    pass


class PDFGenerationError(RenderError):
    """Raised when PDF generation fails."""

    pass


def get_templates_directory() -> Path:
    """Get the directory containing template files.

    Returns:
        Path to templates directory
    """
    current_dir = Path(__file__).parent
    templates_dir = current_dir / "templates"
    return templates_dir


def create_jinja_environment(template_dir: Path | None = None) -> Environment:
    """Create a Jinja2 environment for template rendering.

    Args:
        template_dir: Custom template directory (optional)

    Returns:
        Configured Jinja2 environment
    """
    if template_dir is None:
        template_dir = get_templates_directory()

    if not template_dir.exists():
        raise TemplateNotFoundError(f"Template directory not found: {template_dir}")

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(['html', 'xml']),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Add custom filters
    env.filters['tojson'] = lambda obj, indent=None: _safe_json_serialize(obj, indent)
    
    return env


def render_html(context: dict[str, Any], config: RendererConfig | None = None) -> str:
    """Render complete HTML report from context data.

    Args:
        context: Template context data
        config: Renderer configuration

    Returns:
        Rendered HTML string

    Raises:
        TemplateNotFoundError: If template files are not found
        RenderError: If rendering fails
    """
    if config is None:
        config = RendererConfig()

    # Determine template directory
    template_dir = None
    if config.template_dir:
        template_dir = Path(config.template_dir)

    try:
        env = create_jinja_environment(template_dir)
        
        # Prepare context with renderer config
        render_context = _prepare_render_context(context, config)
        
        # Render each section
        sections = []
        
        # Cover page
        cover_template = env.get_template('cover.html')
        sections.append(cover_template.render(**render_context))
        
        # Executive summary
        exec_template = env.get_template('exec_summary.html')
        sections.append(exec_template.render(**render_context))
        
        # Detailed findings
        findings_template = env.get_template('findings.html')
        sections.append(findings_template.render(**render_context))
        
        # Appendix
        appendix_template = env.get_template('appendix.html')
        sections.append(appendix_template.render(**render_context))
        
        # Combine all sections
        return '\n'.join(sections)

    except Exception as e:
        raise RenderError(f"Failed to render HTML: {e}") from e


def html_to_pdf(html: str, out_pdf: Path, config: RendererConfig | None = None) -> None:
    """Convert HTML string to PDF file using WeasyPrint.

    Args:
        html: HTML content to convert
        out_pdf: Output PDF file path
        config: Renderer configuration

    Raises:
        PDFGenerationError: If PDF generation fails
    """
    if not _check_weasyprint():
        raise PDFGenerationError(
            "WeasyPrint is not available. Please install system dependencies. "
            "See: https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation"
        )
    
    if config is None:
        config = RendererConfig()

    try:
        # Create output directory if it doesn't exist
        out_pdf.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure WeasyPrint
        css_string = None
        if config.template_dir:
            css_path = Path(config.template_dir) / "custom.css"
            if css_path.exists():
                css_string = css_path.read_text()

        # Generate PDF
        document = weasyprint.HTML(string=html)
        
        if css_string:
            css = weasyprint.CSS(string=css_string)
            document.write_pdf(str(out_pdf), stylesheets=[css])
        else:
            document.write_pdf(str(out_pdf))

    except Exception as e:
        raise PDFGenerationError(f"Failed to generate PDF: {e}") from e


def generate_report(
    findings: list[OCSFEnrichedFinding],
    summary: FindingSummary,
    out_pdf: Path,
    config: RendererConfig | None = None,
    **kwargs: Any
) -> None:
    """Generate a complete PDF report from findings and summary data.

    Args:
        findings: List of enriched security findings
        summary: Summary statistics
        out_pdf: Output PDF file path
        config: Renderer configuration
        **kwargs: Additional context data

    Raises:
        RenderError: If report generation fails
        PDFGenerationError: If PDF generation fails
    """
    if config is None:
        config = RendererConfig()

    try:
        # Prepare comprehensive context
        context = _build_report_context(findings, summary, config, **kwargs)
        
        # Render HTML
        html = render_html(context, config)
        
        # Generate PDF
        html_to_pdf(html, out_pdf, config)

    except Exception as e:
        raise RenderError(f"Failed to generate report: {e}") from e


def _prepare_render_context(
    context: dict[str, Any], config: RendererConfig
) -> dict[str, Any]:
    """Prepare the rendering context with configuration and defaults.

    Args:
        context: Base context data
        config: Renderer configuration

    Returns:
        Enhanced context dictionary
    """
    render_context = context.copy()
    
    # Add configuration values
    render_context.update({
        'company_name': config.company_name,
        'logo_path': config.logo_path,
        'include_raw_data': config.include_raw_data,
        'current_date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
    })
    
    # Set default values
    render_context.setdefault('report_title', 'Security Assessment Report')
    render_context.setdefault('assessment_date', render_context['current_date'])
    
    return render_context


def _build_report_context(
    findings: list[OCSFEnrichedFinding],
    summary: FindingSummary,
    config: RendererConfig,
    **kwargs: Any
) -> dict[str, Any]:
    """Build comprehensive context for report generation.

    Args:
        findings: List of enriched findings
        summary: Summary statistics
        config: Renderer configuration
        **kwargs: Additional context data

    Returns:
        Complete context dictionary
    """
    # Calculate additional analytics
    provider_breakdowns = by_provider(findings)
    findings_by_framework = by_framework(findings)
    resource_analysis = unique_resource_analysis(findings)
    
    # Calculate framework scores
    framework_scores = {}
    for framework in summary.frameworks_covered:
        framework_scores[framework] = framework_score(findings, framework)
    
    # Prepare tool versions (would be populated from actual scan metadata)
    tool_versions = {}
    for product in summary.by_product.keys():
        tool_versions[product] = kwargs.get(f'{product}_version', 'Unknown')
    
    # Prepare sample raw data if requested
    raw_sample_data = None
    if config.include_raw_data and findings:
        # Take first finding as sample, with sensitive data redacted
        sample_finding = findings[0]
        raw_sample_data = _redact_sensitive_data(sample_finding.raw)
    
    # Build complete context
    context = {
        'findings': findings,
        'summary': summary,
        'provider_breakdowns': provider_breakdowns,
        'findings_by_framework': findings_by_framework,
        'resource_analysis': resource_analysis,
        'framework_scores': framework_scores,
        'tool_versions': tool_versions,
        'raw_sample_data': raw_sample_data,
        **kwargs  # Include any additional context provided
    }
    
    return context


def _redact_sensitive_data(data: dict[str, Any]) -> dict[str, Any]:
    """Redact sensitive information from raw data.

    Args:
        data: Raw data dictionary

    Returns:
        Data with sensitive information redacted
    """
    if not isinstance(data, dict):
        return data
    
    redacted = {}
    sensitive_keys = {
        'account_id', 'account', 'subscription_id', 'project_id',
        'resource_id', 'arn', 'id', 'uid', 'email', 'phone',
        'ip_address', 'private_ip', 'public_ip'
    }
    
    for key, value in data.items():
        key_lower = key.lower()
        
        if any(key_lower == sensitive_key or key_lower.endswith('_' + sensitive_key) for sensitive_key in sensitive_keys):
            if isinstance(value, str) and len(value) > 4:
                # Redact middle part of string, keep first and last 2 chars
                redacted[key] = value[:2] + '*' * (len(value) - 4) + value[-2:]
            else:
                redacted[key] = '***REDACTED***'
        elif isinstance(value, dict):
            redacted[key] = _redact_sensitive_data(value)
        elif isinstance(value, list):
            redacted[key] = [_redact_sensitive_data(item) if isinstance(item, dict) else item for item in value]
        else:
            redacted[key] = value
    
    return redacted


def _safe_json_serialize(obj: Any, indent: int | None = None) -> str:
    """Safely serialize object to JSON string.

    Args:
        obj: Object to serialize
        indent: JSON indentation

    Returns:
        JSON string
    """
    import json
    from datetime import datetime
    
    def json_serializer(obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, 'model_dump'):
            return obj.model_dump()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)
    
    try:
        return json.dumps(obj, default=json_serializer, indent=indent)
    except Exception:
        return str(obj)


def validate_template_directory(template_dir: Path) -> tuple[bool, list[str]]:
    """Validate that a template directory contains required templates.

    Args:
        template_dir: Path to template directory

    Returns:
        Tuple of (is_valid, list_of_missing_templates)
    """
    required_templates = ['base.html', 'cover.html', 'exec_summary.html', 'findings.html', 'appendix.html']
    missing_templates = []
    
    if not template_dir.exists():
        return False, [f"Template directory does not exist: {template_dir}"]
    
    for template in required_templates:
        template_path = template_dir / template
        if not template_path.exists():
            missing_templates.append(template)
    
    return len(missing_templates) == 0, missing_templates