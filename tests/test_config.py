"""Tests for configuration models."""

import pytest
from pydantic import ValidationError

from cs_kit.cli.config import RendererConfig, RunConfig


class TestRunConfig:
    """Test RunConfig model."""

    def test_valid_config(self) -> None:
        """Test creating a valid configuration."""
        config = RunConfig(
            provider="aws",
            frameworks=["cis_aws_1_4", "nist_csf"],
            regions=["us-east-1", "us-west-2"],
            artifacts_dir="/tmp/artifacts",
            scanners={"prowler": True},
            redact_ids=True,
        )
        
        assert config.provider == "aws"
        assert config.frameworks == ["cis_aws_1_4", "nist_csf"]
        assert config.regions == ["us-east-1", "us-west-2"]
        assert config.artifacts_dir == "/tmp/artifacts"
        assert config.scanners == {"prowler": True}
        assert config.redact_ids is True

    def test_minimal_config(self) -> None:
        """Test creating a minimal configuration with defaults."""
        config = RunConfig(
            provider="gcp",
            artifacts_dir="/tmp/artifacts",
        )
        
        assert config.provider == "gcp"
        assert config.frameworks == []
        assert config.regions == []
        assert config.artifacts_dir == "/tmp/artifacts"
        assert config.scanners == {"prowler": True}
        assert config.redact_ids is True

    def test_invalid_provider(self) -> None:
        """Test validation error for invalid provider."""
        with pytest.raises(ValidationError) as exc_info:
            RunConfig(
                provider="invalid",  # type: ignore
                artifacts_dir="/tmp/artifacts",
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["type"] == "literal_error"
        assert "provider" in errors[0]["loc"]

    def test_missing_required_fields(self) -> None:
        """Test validation error for missing required fields."""
        with pytest.raises(ValidationError) as exc_info:
            RunConfig()  # type: ignore
        
        errors = exc_info.value.errors()
        assert len(errors) == 2  # provider and artifacts_dir are required
        
        missing_fields = {error["loc"][0] for error in errors}
        assert missing_fields == {"provider", "artifacts_dir"}

    def test_extra_fields_forbidden(self) -> None:
        """Test that extra fields are forbidden."""
        with pytest.raises(ValidationError) as exc_info:
            RunConfig(
                provider="aws",
                artifacts_dir="/tmp/artifacts",
                extra_field="not_allowed",  # type: ignore
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["type"] == "extra_forbidden"

    @pytest.mark.parametrize("provider", ["aws", "gcp", "azure"])
    def test_all_valid_providers(self, provider: str) -> None:
        """Test all valid provider values."""
        config = RunConfig(
            provider=provider,  # type: ignore
            artifacts_dir="/tmp/artifacts",
        )
        assert config.provider == provider


class TestRendererConfig:
    """Test RendererConfig model."""

    def test_default_config(self) -> None:
        """Test creating a configuration with all defaults."""
        config = RendererConfig()
        
        assert config.template_dir is None
        assert config.logo_path is None
        assert config.company_name == "Security Assessment"
        assert config.include_raw_data is False

    def test_custom_config(self) -> None:
        """Test creating a custom configuration."""
        config = RendererConfig(
            template_dir="/custom/templates",
            logo_path="/path/to/logo.png",
            company_name="ACME Corp",
            include_raw_data=True,
        )
        
        assert config.template_dir == "/custom/templates"
        assert config.logo_path == "/path/to/logo.png"
        assert config.company_name == "ACME Corp"
        assert config.include_raw_data is True

    def test_partial_config(self) -> None:
        """Test creating a partial configuration."""
        config = RendererConfig(
            company_name="Test Company",
            include_raw_data=True,
        )
        
        assert config.template_dir is None
        assert config.logo_path is None
        assert config.company_name == "Test Company"
        assert config.include_raw_data is True

    def test_extra_fields_forbidden(self) -> None:
        """Test that extra fields are forbidden."""
        with pytest.raises(ValidationError) as exc_info:
            RendererConfig(
                extra_field="not_allowed",  # type: ignore
            )
        
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]["type"] == "extra_forbidden"