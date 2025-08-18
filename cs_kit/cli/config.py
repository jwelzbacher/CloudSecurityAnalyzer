"""Configuration models for CS Kit."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RunConfig(BaseModel):
    """Configuration for a security scan run."""

    provider: Literal["aws", "gcp", "azure"] = Field(
        ..., description="Cloud provider to scan"
    )
    frameworks: list[str] = Field(
        default_factory=list, description="Compliance frameworks to apply"
    )
    regions: list[str] = Field(
        default_factory=list, description="Regions to scan (provider-specific)"
    )
    artifacts_dir: str = Field(
        ..., description="Directory to store scan artifacts and results"
    )
    scanners: dict[str, bool] = Field(
        default_factory=lambda: {"prowler": True},
        description="Security scanners to enable/disable",
    )
    redact_ids: bool = Field(
        default=True, description="Redact sensitive IDs in reports"
    )

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class RendererConfig(BaseModel):
    """Configuration for report rendering."""

    template_dir: str | None = Field(
        default=None, description="Custom template directory"
    )
    logo_path: str | None = Field(
        default=None, description="Path to company logo for reports"
    )
    company_name: str = Field(
        default="Security Assessment", description="Company name for reports"
    )
    include_raw_data: bool = Field(
        default=False, description="Include raw scanner data in appendix"
    )

    model_config = ConfigDict(extra="forbid", validate_assignment=True)