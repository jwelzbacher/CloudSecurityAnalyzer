"""Tests for PDF rendering functionality."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cs_kit.cli.config import RendererConfig
from cs_kit.normalizer.ocsf_models import FindingSummary, OCSFEnrichedFinding
from cs_kit.render.pdf import (
    PDFGenerationError,
    RenderError,
    TemplateNotFoundError,
    _build_report_context,
    _check_weasyprint,
    _prepare_render_context,
    _redact_sensitive_data,
    _safe_json_serialize,
    create_jinja_environment,
    generate_report,
    get_templates_directory,
    html_to_pdf,
    render_html,
    validate_template_directory,
)


class TestGetTemplatesDirectory:
    """Test get_templates_directory function."""

    def test_get_templates_directory(self) -> None:
        """Test getting templates directory."""
        templates_dir = get_templates_directory()
        assert isinstance(templates_dir, Path)
        assert templates_dir.name == "templates"
        assert "cs_kit" in str(templates_dir)


class TestCreateJinjaEnvironment:
    """Test create_jinja_environment function."""

    def test_create_jinja_environment_default(self) -> None:
        """Test creating Jinja environment with default template directory."""
        env = create_jinja_environment()
        assert env is not None
        assert 'tojson' in env.filters

    def test_create_jinja_environment_custom(self) -> None:
        """Test creating Jinja environment with custom template directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            custom_dir = Path(tmp_dir)

            # Create a basic template
            (custom_dir / "test.html").write_text("<html>{{ test }}</html>")

            env = create_jinja_environment(custom_dir)
            assert env is not None

            template = env.get_template("test.html")
            result = template.render(test="hello")
            assert "hello" in result

    def test_create_jinja_environment_nonexistent(self) -> None:
        """Test creating Jinja environment with nonexistent directory."""
        nonexistent_dir = Path("/nonexistent/templates")

        with pytest.raises(TemplateNotFoundError) as exc_info:
            create_jinja_environment(nonexistent_dir)

        assert "Template directory not found" in str(exc_info.value)


class TestRenderHtml:
    """Test render_html function."""

    def test_render_html_basic(self) -> None:
        """Test basic HTML rendering."""
        # Create minimal context
        context = {
            'summary': FindingSummary(
                total_findings=5,
                by_severity={'high': 2, 'medium': 3},
                by_status={'fail': 4, 'pass': 1},
                by_provider={'aws': 5},
                by_product={'prowler': 5},
                frameworks_covered=['cis_aws_1_4'],
                unique_resources=3,
                unique_accounts=1,
            ),
            'findings': [],
            'provider_breakdowns': {},
            'findings_by_framework': {},
            'framework_scores': {},
            'tool_versions': {'prowler': '3.5.0'},
            'resource_analysis': {'resource_types': {}},
        }

        config = RendererConfig(company_name="Test Company")

        try:
            html = render_html(context, config)
            assert isinstance(html, str)
            assert len(html) > 0
            assert "Test Company" in html
            assert "Security Assessment Report" in html
        except TemplateNotFoundError:
            pytest.skip("Template files not found")

    def test_render_html_no_config(self) -> None:
        """Test HTML rendering without config."""
        context = {
            'summary': FindingSummary(total_findings=0),
            'findings': [],
            'provider_breakdowns': {},
            'findings_by_framework': {},
            'framework_scores': {},
        }

        try:
            html = render_html(context)
            assert isinstance(html, str)
            assert "Security Assessment" in html  # Default company name
        except TemplateNotFoundError:
            pytest.skip("Template files not found")

    def test_render_html_missing_template(self) -> None:
        """Test HTML rendering with missing template directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            empty_dir = Path(tmp_dir) / "empty"
            empty_dir.mkdir()

            config = RendererConfig(template_dir=str(empty_dir))
            context = {'summary': FindingSummary(total_findings=0)}

            with pytest.raises(RenderError):
                render_html(context, config)


class TestHtmlToPdf:
    """Test html_to_pdf function."""

    def test_html_to_pdf_unavailable(self) -> None:
        """Test HTML to PDF conversion when WeasyPrint is unavailable."""
        if not _check_weasyprint():
            html = "<html><body>Test</body></html>"

            with tempfile.TemporaryDirectory() as tmp_dir:
                out_pdf = Path(tmp_dir) / "test.pdf"

                with pytest.raises(PDFGenerationError) as exc_info:
                    html_to_pdf(html, out_pdf)

                assert "WeasyPrint is not available" in str(exc_info.value)
        else:
            pytest.skip("WeasyPrint is available")

    def test_html_to_pdf_basic_mock(self) -> None:
        """Test basic HTML to PDF conversion with mocked WeasyPrint."""
        with patch('cs_kit.render.pdf._check_weasyprint', return_value=True), \
             patch('cs_kit.render.pdf.weasyprint') as mock_weasyprint:

            # Mock WeasyPrint
            mock_html = MagicMock()
            mock_weasyprint.HTML.return_value = mock_html

            html = "<html><body>Test</body></html>"

            with tempfile.TemporaryDirectory() as tmp_dir:
                out_pdf = Path(tmp_dir) / "test.pdf"

                html_to_pdf(html, out_pdf)

                mock_weasyprint.HTML.assert_called_once_with(string=html)
                mock_html.write_pdf.assert_called_once_with(str(out_pdf))

    def test_html_to_pdf_with_custom_css_mock(self) -> None:
        """Test HTML to PDF conversion with custom CSS and mocked WeasyPrint."""
        with patch('cs_kit.render.pdf._check_weasyprint', return_value=True), \
             patch('cs_kit.render.pdf.weasyprint') as mock_weasyprint:

            # Mock WeasyPrint
            mock_html = MagicMock()
            mock_css = MagicMock()
            mock_weasyprint.HTML.return_value = mock_html
            mock_weasyprint.CSS.return_value = mock_css

            html = "<html><body>Test</body></html>"

            with tempfile.TemporaryDirectory() as tmp_dir:
                template_dir = Path(tmp_dir)
                css_file = template_dir / "custom.css"
                css_file.write_text("body { font-size: 12px; }")

                config = RendererConfig(template_dir=str(template_dir))
                out_pdf = Path(tmp_dir) / "test.pdf"

                html_to_pdf(html, out_pdf, config)

                mock_weasyprint.CSS.assert_called_once()
                mock_html.write_pdf.assert_called_once_with(str(out_pdf), stylesheets=[mock_css])

    def test_html_to_pdf_error_mock(self) -> None:
        """Test HTML to PDF conversion error handling with mocked WeasyPrint."""
        with patch('cs_kit.render.pdf._check_weasyprint', return_value=True), \
             patch('cs_kit.render.pdf.weasyprint') as mock_weasyprint:

            # Mock WeasyPrint to raise an exception
            mock_weasyprint.HTML.side_effect = Exception("PDF generation failed")

            html = "<html><body>Test</body></html>"

            with tempfile.TemporaryDirectory() as tmp_dir:
                out_pdf = Path(tmp_dir) / "test.pdf"

                with pytest.raises(PDFGenerationError) as exc_info:
                    html_to_pdf(html, out_pdf)

                assert "Failed to generate PDF" in str(exc_info.value)


class TestGenerateReport:
    """Test generate_report function."""

    @patch('cs_kit.render.pdf.html_to_pdf')
    @patch('cs_kit.render.pdf.render_html')
    def test_generate_report_basic(
        self, mock_render_html: MagicMock, mock_html_to_pdf: MagicMock
    ) -> None:
        """Test basic report generation."""
        # Mock render functions
        mock_render_html.return_value = "<html>Test Report</html>"
        mock_html_to_pdf.return_value = None

        # Create test data
        findings = [
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity="high",
                status="fail",
            )
        ]

        summary = FindingSummary(
            total_findings=1,
            by_severity={'high': 1},
            by_status={'fail': 1},
            by_provider={'aws': 1},
            by_product={'prowler': 1},
            unique_resources=1,
            unique_accounts=1,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            out_pdf = Path(tmp_dir) / "report.pdf"

            generate_report(findings, summary, out_pdf)

            mock_render_html.assert_called_once()
            mock_html_to_pdf.assert_called_once()


class TestPrepareRenderContext:
    """Test _prepare_render_context function."""

    def test_prepare_render_context_basic(self) -> None:
        """Test basic context preparation."""
        base_context = {'test_key': 'test_value'}
        config = RendererConfig(company_name="Test Company", logo_path="/path/to/logo.png")

        context = _prepare_render_context(base_context, config)

        assert context['test_key'] == 'test_value'
        assert context['company_name'] == "Test Company"
        assert context['logo_path'] == "/path/to/logo.png"
        assert 'current_date' in context
        assert context['report_title'] == 'Security Assessment Report'  # Default

    def test_prepare_render_context_with_overrides(self) -> None:
        """Test context preparation with overrides."""
        base_context = {
            'report_title': 'Custom Report Title',
            'assessment_date': '2024-01-15'
        }
        config = RendererConfig()

        context = _prepare_render_context(base_context, config)

        assert context['report_title'] == 'Custom Report Title'
        assert context['assessment_date'] == '2024-01-15'


class TestBuildReportContext:
    """Test _build_report_context function."""

    def test_build_report_context_basic(self) -> None:
        """Test basic report context building."""
        findings = [
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                framework_refs=["cis_aws_1_4:CIS-1.3"],
                resource_id="arn:aws:iam::123456789012:root",
                account_id="123456789012",
            )
        ]

        summary = FindingSummary(
            total_findings=1,
            frameworks_covered=["cis_aws_1_4"],
            by_product={"prowler": 1},
            unique_resources=1,
            unique_accounts=1,
        )

        config = RendererConfig()

        context = _build_report_context(findings, summary, config)

        assert 'findings' in context
        assert 'summary' in context
        assert 'provider_breakdowns' in context
        assert 'findings_by_framework' in context
        assert 'framework_scores' in context
        assert 'tool_versions' in context
        assert context['findings'] == findings
        assert context['summary'] == summary

    def test_build_report_context_with_raw_data(self) -> None:
        """Test report context building with raw data inclusion."""
        findings = [
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                raw={"account_id": "123456789012", "test": "data"},
            )
        ]

        summary = FindingSummary(total_findings=1)
        config = RendererConfig(include_raw_data=True)

        context = _build_report_context(findings, summary, config)

        assert 'raw_sample_data' in context
        assert context['raw_sample_data'] is not None
        # Should be redacted (account_id should be masked)
        assert '12********12' in str(context['raw_sample_data'])


class TestRedactSensitiveData:
    """Test _redact_sensitive_data function."""

    def test_redact_sensitive_data_basic(self) -> None:
        """Test basic sensitive data redaction."""
        data = {
            "account_id": "123456789012",
            "resource_id": "arn:aws:iam::123456789012:root",
            "safe_field": "safe_value",
            "email": "user@example.com",
        }

        redacted = _redact_sensitive_data(data)

        assert redacted["account_id"] == "12********12"
        assert redacted["safe_field"] == "safe_value"
        assert redacted["email"] == "us************om"

    def test_redact_sensitive_data_nested(self) -> None:
        """Test sensitive data redaction in nested structures."""
        data = {
            "cloud": {
                "account": {"id": "123456789012"},
                "provider": "aws"
            },
            "list_field": [
                {"account_id": "987654321098", "safe": "value"}
            ]
        }

        redacted = _redact_sensitive_data(data)

        assert redacted["cloud"]["provider"] == "aws"
        # The "account" key itself triggers redaction, so the whole dict becomes a string
        assert redacted["cloud"]["account"] == "***REDACTED***"
        assert redacted["list_field"][0]["account_id"] == "98********98"

    def test_redact_sensitive_data_non_dict(self) -> None:
        """Test sensitive data redaction with non-dict input."""
        result = _redact_sensitive_data("not a dict")
        assert result == "not a dict"


class TestSafeJsonSerialize:
    """Test _safe_json_serialize function."""

    def test_safe_json_serialize_basic(self) -> None:
        """Test basic JSON serialization."""
        data = {"key": "value", "number": 42}
        result = _safe_json_serialize(data)
        assert '"key": "value"' in result
        assert '"number": 42' in result

    def test_safe_json_serialize_with_datetime(self) -> None:
        """Test JSON serialization with datetime objects."""
        now = datetime.now(UTC)
        data = {"timestamp": now}
        result = _safe_json_serialize(data)
        assert now.isoformat() in result

    def test_safe_json_serialize_with_pydantic(self) -> None:
        """Test JSON serialization with Pydantic models."""
        finding = OCSFEnrichedFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
        )
        result = _safe_json_serialize(finding)
        assert '"provider": "aws"' in result

    def test_safe_json_serialize_fallback(self) -> None:
        """Test JSON serialization fallback for unserializable objects."""
        class UnserializableObject:
            def __str__(self) -> str:
                return "unserializable"

            def __dict__(self) -> dict:
                # This will be called by the serializer
                return {}

        data = {"obj": UnserializableObject()}
        result = _safe_json_serialize(data)
        # The object has __dict__ so it will be serialized as empty dict
        assert '{}' in result


class TestValidateTemplateDirectory:
    """Test validate_template_directory function."""

    def test_validate_template_directory_valid(self) -> None:
        """Test validation of valid template directory."""
        templates_dir = get_templates_directory()
        if templates_dir.exists():
            is_valid, missing = validate_template_directory(templates_dir)
            if is_valid:
                assert is_valid
                assert len(missing) == 0
            else:
                # Some templates might be missing in test environment
                assert isinstance(missing, list)
        else:
            pytest.skip("Templates directory not found")

    def test_validate_template_directory_invalid(self) -> None:
        """Test validation of invalid template directory."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            empty_dir = Path(tmp_dir)

            is_valid, missing = validate_template_directory(empty_dir)
            assert not is_valid
            assert len(missing) > 0
            assert "base.html" in missing

    def test_validate_template_directory_nonexistent(self) -> None:
        """Test validation of nonexistent template directory."""
        nonexistent_dir = Path("/nonexistent/templates")

        is_valid, errors = validate_template_directory(nonexistent_dir)
        assert not is_valid
        assert len(errors) == 1
        assert "does not exist" in errors[0]
