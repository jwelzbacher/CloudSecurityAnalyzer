"""OCSF (Open Cybersecurity Schema Framework) models for posture findings."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class OCSFFinding(BaseModel):
    """OCSF-compliant security finding model."""

    time: datetime = Field(..., description="Timestamp of the finding")
    provider: Literal["aws", "gcp", "azure"] = Field(
        ..., description="Cloud provider"
    )
    product: str = Field(..., description="Security tool that generated the finding")
    class_uid: int | None = Field(
        default=None, description="OCSF class unique identifier"
    )
    class_name: str | None = Field(
        default=None, description="OCSF class name"
    )
    severity: Literal["critical", "high", "medium", "low", "informational"] | None = (
        Field(default=None, description="Finding severity level")
    )
    status: Literal["pass", "fail", "not_applicable", "informational"] | None = Field(
        default=None, description="Finding status"
    )
    resource_id: str | None = Field(
        default=None, description="Cloud resource identifier"
    )
    account_id: str | None = Field(
        default=None, description="Cloud account identifier"
    )
    region: str | None = Field(
        default=None, description="Cloud region"
    )
    check_id: str | None = Field(
        default=None, description="Vendor-specific check identifier"
    )
    title: str | None = Field(
        default=None, description="Finding title or summary"
    )
    description: str | None = Field(
        default=None, description="Detailed finding description"
    )
    remediation: str | None = Field(
        default=None, description="Remediation guidance"
    )
    raw: dict[str, Any] = Field(
        default_factory=dict, description="Original raw finding data"
    )

    model_config = ConfigDict(extra="allow", validate_assignment=True)


class OCSFResource(BaseModel):
    """Cloud resource information."""

    uid: str | None = Field(default=None, description="Resource unique identifier")
    type: str | None = Field(default=None, description="Resource type")
    region: str | None = Field(default=None, description="Resource region")
    name: str | None = Field(default=None, description="Resource name")
    tags: dict[str, str] = Field(
        default_factory=dict, description="Resource tags"
    )

    model_config = ConfigDict(extra="allow")


class OCSFCloud(BaseModel):
    """Cloud environment information."""

    provider: Literal["aws", "gcp", "azure"] = Field(
        ..., description="Cloud provider"
    )
    account_uid: str | None = Field(
        default=None, description="Cloud account identifier"
    )
    region: str | None = Field(default=None, description="Cloud region")
    availability_zone: str | None = Field(
        default=None, description="Availability zone"
    )

    model_config = ConfigDict(extra="allow")


class OCSFCompliance(BaseModel):
    """Compliance framework information."""

    requirements: list[str] = Field(
        default_factory=list, description="Compliance requirement identifiers"
    )
    frameworks: list[str] = Field(
        default_factory=list, description="Compliance framework names"
    )

    model_config = ConfigDict(extra="allow")


class OCSFEnrichedFinding(OCSFFinding):
    """Extended OCSF finding with additional enrichment data."""

    resource: OCSFResource | None = Field(
        default=None, description="Detailed resource information"
    )
    cloud: OCSFCloud | None = Field(
        default=None, description="Detailed cloud information"
    )
    compliance: OCSFCompliance | None = Field(
        default=None, description="Compliance framework mappings"
    )
    framework_refs: list[str] = Field(
        default_factory=list, description="Framework reference identifiers"
    )
    risk_score: float | None = Field(
        default=None, description="Calculated risk score (0-10)"
    )
    tags: dict[str, str] = Field(
        default_factory=dict, description="Additional metadata tags"
    )

    model_config = ConfigDict(extra="allow", validate_assignment=True)


class FindingSummary(BaseModel):
    """Summary statistics for a collection of findings."""

    total_findings: int = Field(..., description="Total number of findings")
    by_severity: dict[str, int] = Field(
        default_factory=dict, description="Findings count by severity"
    )
    by_status: dict[str, int] = Field(
        default_factory=dict, description="Findings count by status"
    )
    by_provider: dict[str, int] = Field(
        default_factory=dict, description="Findings count by provider"
    )
    by_product: dict[str, int] = Field(
        default_factory=dict, description="Findings count by security product"
    )
    frameworks_covered: list[str] = Field(
        default_factory=list, description="List of compliance frameworks covered"
    )
    scan_time_range: dict[str, datetime | None] = Field(
        default_factory=lambda: {"start": None, "end": None},
        description="Time range of the scan",
    )
    unique_resources: int = Field(
        default=0, description="Number of unique resources scanned"
    )
    unique_accounts: int = Field(
        default=0, description="Number of unique accounts scanned"
    )

    model_config = ConfigDict(extra="forbid", validate_assignment=True)