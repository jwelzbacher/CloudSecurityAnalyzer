"""OCSF data parsing and normalization."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from cs_kit.normalizer.ocsf_models import OCSFFinding


def parse_ocsf(
    path: Path, provider: Literal["aws", "gcp", "azure"], product: str
) -> list[OCSFFinding]:
    """Parse OCSF JSON data into normalized findings.

    Args:
        path: Path to the OCSF JSON file
        provider: Cloud provider
        product: Security product name

    Returns:
        List of normalized OCSF findings

    Raises:
        FileNotFoundError: If the file doesn't exist
        json.JSONDecodeError: If the file is not valid JSON
        ValueError: If the data structure is invalid
    """
    if not path.exists():
        raise FileNotFoundError(f"OCSF file not found: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(f"Invalid JSON in {path}: {e.msg}", e.doc, e.pos)

    # Handle both single objects and arrays
    if isinstance(data, dict):
        data = [data]
    elif not isinstance(data, list):
        raise ValueError(f"Expected JSON object or array in {path}, got {type(data)}")

    findings = []
    for i, raw_finding in enumerate(data):
        if not isinstance(raw_finding, dict):
            raise ValueError(
                f"Expected JSON object at index {i} in {path}, got {type(raw_finding)}"
            )

        try:
            finding = _parse_single_finding(raw_finding, provider, product)
            findings.append(finding)
        except Exception as e:
            raise ValueError(f"Error parsing finding at index {i} in {path}: {e}") from e

    return findings


def _parse_single_finding(
    raw_finding: dict[str, Any], provider: Literal["aws", "gcp", "azure"], product: str
) -> OCSFFinding:
    """Parse a single raw finding into an OCSF finding.

    Args:
        raw_finding: Raw finding data
        provider: Cloud provider
        product: Security product name

    Returns:
        Normalized OCSF finding
    """
    # Extract timestamp
    time_str = raw_finding.get("time")
    if time_str:
        if isinstance(time_str, str):
            # Handle ISO format timestamps
            try:
                time = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            except ValueError:
                # Fallback to current time if parsing fails
                time = datetime.now(timezone.utc)
        else:
            time = datetime.now(timezone.utc)
    else:
        time = datetime.now(timezone.utc)

    # Extract basic OCSF fields
    class_uid = raw_finding.get("class_uid")
    class_name = raw_finding.get("class_name")

    # Extract severity and status with normalization
    severity = _normalize_severity(raw_finding.get("severity"))
    status = _normalize_status(raw_finding.get("status"))

    # Extract resource information
    resource_id = _extract_resource_id(raw_finding)
    account_id = _extract_account_id(raw_finding)
    region = _extract_region(raw_finding)

    # Extract finding details
    check_id = _extract_check_id(raw_finding)
    title = _extract_title(raw_finding)
    description = _extract_description(raw_finding)
    remediation = _extract_remediation(raw_finding)

    return OCSFFinding(
        time=time,
        provider=provider,
        product=product,
        class_uid=class_uid,
        class_name=class_name,
        severity=severity,
        status=status,
        resource_id=resource_id,
        account_id=account_id,
        region=region,
        check_id=check_id,
        title=title,
        description=description,
        remediation=remediation,
        raw=raw_finding,
    )


def _normalize_severity(
    severity: Any,
) -> Literal["critical", "high", "medium", "low", "informational"] | None:
    """Normalize severity values to standard OCSF levels.

    Args:
        severity: Raw severity value

    Returns:
        Normalized severity or None
    """
    if not severity:
        return None

    severity_str = str(severity).lower().strip()

    # Map common severity variations to standard values
    severity_map = {
        "critical": "critical",
        "crit": "critical",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "informational",
        "informational": "informational",
        "information": "informational",
        "notice": "informational",
    }

    return severity_map.get(severity_str)  # type: ignore


def _normalize_status(
    status: Any,
) -> Literal["pass", "fail", "not_applicable", "informational"] | None:
    """Normalize status values to standard OCSF levels.

    Args:
        status: Raw status value

    Returns:
        Normalized status or None
    """
    if not status:
        return None

    status_str = str(status).lower().strip()

    # Map common status variations to standard values
    status_map = {
        "pass": "pass",
        "passed": "pass",
        "success": "pass",
        "ok": "pass",
        "fail": "fail",
        "failed": "fail",
        "failure": "fail",
        "error": "fail",
        "not_applicable": "not_applicable",
        "n/a": "not_applicable",
        "na": "not_applicable",
        "skip": "not_applicable",
        "skipped": "not_applicable",
        "info": "informational",
        "informational": "informational",
        "information": "informational",
    }

    return status_map.get(status_str)  # type: ignore


def _extract_resource_id(raw_finding: dict[str, Any]) -> str | None:
    """Extract resource ID from various possible locations in the raw finding."""
    # First try to get from resources array (OCSF format)
    resources = raw_finding.get("resources", [])
    if resources and len(resources) > 0:
        first_resource = resources[0]
        if "uid" in first_resource:
            return str(first_resource["uid"])
        if "name" in first_resource:
            return str(first_resource["name"])
    
    # Try different common locations for resource ID
    locations = [
        ["resource", "uid"],
        ["resource", "id"],
        ["resource_uid"],
        ["resource_id"],
        ["arn"],
        ["resource_arn"],
    ]

    for location in locations:
        value = _get_nested_value(raw_finding, location)
        if value:
            return str(value)

    return None


def _extract_account_id(raw_finding: dict[str, Any]) -> str | None:
    """Extract account ID from various possible locations in the raw finding."""
    # First try to get from resources array (OCSF format)
    resources = raw_finding.get("resources", [])
    if resources and len(resources) > 0:
        first_resource = resources[0]
        if "account_uid" in first_resource:
            return str(first_resource["account_uid"])
    
    locations = [
        ["cloud", "account", "uid"],
        ["cloud", "account", "id"],
        ["account_uid"],
        ["account_id"],
        ["account"],
    ]

    for location in locations:
        value = _get_nested_value(raw_finding, location)
        if value:
            return str(value)

    return None


def _extract_region(raw_finding: dict[str, Any]) -> str | None:
    """Extract region from various possible locations in the raw finding."""
    # First try to get from resources array (OCSF format)
    resources = raw_finding.get("resources", [])
    if resources and len(resources) > 0:
        first_resource = resources[0]
        if "region" in first_resource:
            return str(first_resource["region"])
    
    locations = [
        ["cloud", "region"],
        ["resource", "region"],
        ["region"],
    ]

    for location in locations:
        value = _get_nested_value(raw_finding, location)
        if value:
            return str(value)

    return None


def _extract_check_id(raw_finding: dict[str, Any]) -> str | None:
    """Extract check/rule ID from various possible locations in the raw finding."""
    locations = [
        ["finding", "uid"],
        ["finding", "id"],
        ["check_id"],
        ["rule_id"],
        ["uid"],
        ["id"],
    ]

    for location in locations:
        value = _get_nested_value(raw_finding, location)
        if value:
            return str(value)

    return None


def _extract_title(raw_finding: dict[str, Any]) -> str | None:
    """Extract title from various possible locations in the raw finding."""
    locations = [
        ["finding", "title"],
        ["title"],
        ["summary"],
        ["name"],
    ]

    for location in locations:
        value = _get_nested_value(raw_finding, location)
        if value:
            return str(value)

    return None


def _extract_description(raw_finding: dict[str, Any]) -> str | None:
    """Extract description from various possible locations in the raw finding."""
    locations = [
        ["finding", "desc"],
        ["finding", "description"],
        ["description"],
        ["desc"],
        ["message"],
    ]

    for location in locations:
        value = _get_nested_value(raw_finding, location)
        if value:
            return str(value)

    return None


def _extract_remediation(raw_finding: dict[str, Any]) -> str | None:
    """Extract remediation from various possible locations in the raw finding."""
    locations = [
        ["finding", "remediation", "desc"],
        ["finding", "remediation", "description"],
        ["remediation", "desc"],
        ["remediation", "description"],
        ["remediation"],
        ["recommendation"],
        ["fix"],
    ]

    for location in locations:
        value = _get_nested_value(raw_finding, location)
        if value:
            return str(value)

    return None


def _get_nested_value(data: dict[str, Any], keys: list[str]) -> Any:
    """Get a nested value from a dictionary using a list of keys.

    Args:
        data: Dictionary to search
        keys: List of keys representing the path

    Returns:
        Value at the path or None if not found
    """
    current = data
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return None
    return current