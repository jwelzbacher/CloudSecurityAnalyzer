"""Compliance framework mapping functionality."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from cs_kit.normalizer.ocsf_models import OCSFEnrichedFinding, OCSFFinding


class MappingRule(BaseModel):
    """A single mapping rule from scanner output to compliance framework."""

    source: str = Field(..., description="Source check identifier (scanner:check_id)")
    target: str = Field(..., description="Target compliance control identifier")
    title: str = Field(..., description="Human-readable title")
    description: str = Field(..., description="Detailed description")
    severity: str | None = Field(default=None, description="Override severity")

    model_config = ConfigDict(extra="forbid")


class MappingCategory(BaseModel):
    """A category grouping related compliance controls."""

    id: str = Field(..., description="Category identifier")
    name: str = Field(..., description="Human-readable category name")
    controls: list[str] = Field(..., description="List of control identifiers")

    model_config = ConfigDict(extra="forbid")


class MappingMetadata(BaseModel):
    """Metadata about the mapping file."""

    created_date: str | None = Field(default=None, description="Creation date")
    updated_date: str | None = Field(default=None, description="Last update date")
    author: str | None = Field(default=None, description="Author")
    source_url: str | None = Field(default=None, description="Source URL")
    tags: list[str] = Field(default_factory=list, description="Tags")

    model_config = ConfigDict(extra="allow")


class ComplianceMapping(BaseModel):
    """Complete compliance framework mapping."""

    map_id: str = Field(..., description="Unique mapping identifier")
    name: str = Field(..., description="Human-readable mapping name")
    version: str = Field(..., description="Mapping version")
    description: str = Field(..., description="Mapping description")
    framework_type: str = Field(..., description="Type of framework (cis, nist, etc.)")
    provider: str | None = Field(default=None, description="Cloud provider")
    rules: list[MappingRule] = Field(..., description="Mapping rules")
    categories: list[MappingCategory] = Field(
        default_factory=list, description="Control categories"
    )
    metadata: MappingMetadata | None = Field(
        default=None, description="Additional metadata"
    )

    model_config = ConfigDict(extra="forbid")


class MappingLoadError(Exception):
    """Raised when mapping file cannot be loaded."""

    pass


class MappingNotFoundError(MappingLoadError):
    """Raised when mapping file is not found."""

    pass


def get_mappings_directory() -> Path:
    """Get the directory containing mapping files.

    Returns:
        Path to mappings directory
    """
    # Get the directory containing this file
    current_dir = Path(__file__).parent
    # Go up to cs_kit, then down to mappings
    mappings_dir = current_dir.parent / "mappings"
    return mappings_dir


def list_available_mappings() -> list[str]:
    """List all available mapping IDs.

    Returns:
        List of mapping identifiers
    """
    mappings_dir = get_mappings_directory()
    if not mappings_dir.exists():
        return []

    mapping_ids = []
    for yaml_file in mappings_dir.glob("*.yaml"):
        if yaml_file.name != "__init__.py":
            # Use filename without extension as mapping ID
            mapping_ids.append(yaml_file.stem)

    return sorted(mapping_ids)


def load_mapping(map_id: str) -> ComplianceMapping:
    """Load a compliance mapping from YAML file.

    Args:
        map_id: Mapping identifier

    Returns:
        Loaded compliance mapping

    Raises:
        MappingNotFoundError: If mapping file is not found
        MappingLoadError: If mapping file cannot be parsed
    """
    mappings_dir = get_mappings_directory()
    mapping_file = mappings_dir / f"{map_id}.yaml"

    if not mapping_file.exists():
        available = list_available_mappings()
        raise MappingNotFoundError(
            f"Mapping '{map_id}' not found. Available mappings: {available}"
        )

    try:
        with open(mapping_file, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise MappingLoadError(f"Invalid YAML structure in {mapping_file}")

        return ComplianceMapping(**data)

    except yaml.YAMLError as e:
        raise MappingLoadError(f"Error parsing YAML file {mapping_file}: {e}") from e
    except Exception as e:
        raise MappingLoadError(f"Error loading mapping {map_id}: {e}") from e


def apply_mapping(
    findings: list[OCSFFinding], map_ids: list[str]
) -> list[OCSFEnrichedFinding]:
    """Apply compliance mappings to findings.

    Args:
        findings: List of OCSF findings
        map_ids: List of mapping identifiers to apply

    Returns:
        List of enriched findings with framework references

    Raises:
        MappingNotFoundError: If a mapping is not found
        MappingLoadError: If a mapping cannot be loaded
    """
    # Load all mappings
    mappings = {}
    for map_id in map_ids:
        mappings[map_id] = load_mapping(map_id)

    # Build lookup table for efficient mapping
    check_to_controls = {}
    for map_id, mapping in mappings.items():
        for rule in mapping.rules:
            source_key = rule.source
            if source_key not in check_to_controls:
                check_to_controls[source_key] = []
            check_to_controls[source_key].append({
                "framework": map_id,
                "control": rule.target,
                "title": rule.title,
                "description": rule.description,
                "severity_override": rule.severity,
            })

    # Apply mappings to findings
    enriched_findings = []
    for finding in findings:
        # Create enriched finding
        enriched_data = finding.model_dump()
        enriched_finding = OCSFEnrichedFinding(**enriched_data)

        # Build source key for lookup
        if finding.check_id:
            source_key = f"{finding.product}:{finding.check_id}"

            # Find matching controls
            if source_key in check_to_controls:
                framework_refs = []
                for control_info in check_to_controls[source_key]:
                    framework_refs.append(
                        f"{control_info['framework']}:{control_info['control']}"
                    )

                    # Apply severity override if specified
                    if (
                        control_info['severity_override']
                        and not enriched_finding.severity
                    ):
                        enriched_finding.severity = control_info['severity_override']  # type: ignore

                enriched_finding.framework_refs = framework_refs

        enriched_findings.append(enriched_finding)

    return enriched_findings


def get_framework_controls(map_id: str) -> dict[str, list[str]]:
    """Get all controls organized by category for a framework.

    Args:
        map_id: Mapping identifier

    Returns:
        Dictionary mapping category names to control lists

    Raises:
        MappingNotFoundError: If mapping is not found
        MappingLoadError: If mapping cannot be loaded
    """
    mapping = load_mapping(map_id)

    controls_by_category = {}
    for category in mapping.categories:
        controls_by_category[category.name] = category.controls

    # If no categories defined, create a default one with all controls
    if not controls_by_category:
        all_controls = [rule.target for rule in mapping.rules]
        controls_by_category["All Controls"] = sorted(set(all_controls))

    return controls_by_category


def validate_mapping_file(mapping_file: Path) -> tuple[bool, list[str]]:
    """Validate a mapping YAML file.

    Args:
        mapping_file: Path to mapping file

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []

    if not mapping_file.exists():
        return False, [f"File does not exist: {mapping_file}"]

    try:
        with open(mapping_file, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        # Try to parse as ComplianceMapping
        ComplianceMapping(**data)
        return True, []

    except yaml.YAMLError as e:
        errors.append(f"YAML parsing error: {e}")
    except Exception as e:
        errors.append(f"Validation error: {e}")

    return False, errors
