"""Rollups and summaries for security findings analysis."""

from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from cs_kit.normalizer.ocsf_models import FindingSummary, OCSFFinding, OCSFEnrichedFinding


def severity_counts(findings: list[OCSFFinding | OCSFEnrichedFinding]) -> dict[str, int]:
    """Count findings by severity level.

    Args:
        findings: List of findings to analyze

    Returns:
        Dictionary mapping severity levels to counts
    """
    severity_counter = Counter()
    
    for finding in findings:
        severity = finding.severity or "unknown"
        severity_counter[severity] += 1
    
    return dict(severity_counter)


def status_counts(findings: list[OCSFFinding | OCSFEnrichedFinding]) -> dict[str, int]:
    """Count findings by status.

    Args:
        findings: List of findings to analyze

    Returns:
        Dictionary mapping status values to counts
    """
    status_counter = Counter()
    
    for finding in findings:
        status = finding.status or "unknown"
        status_counter[status] += 1
    
    return dict(status_counter)


def provider_counts(findings: list[OCSFFinding | OCSFEnrichedFinding]) -> dict[str, int]:
    """Count findings by cloud provider.

    Args:
        findings: List of findings to analyze

    Returns:
        Dictionary mapping providers to counts
    """
    provider_counter = Counter()
    
    for finding in findings:
        provider_counter[finding.provider] += 1
    
    return dict(provider_counter)


def product_counts(findings: list[OCSFFinding | OCSFEnrichedFinding]) -> dict[str, int]:
    """Count findings by security product.

    Args:
        findings: List of findings to analyze

    Returns:
        Dictionary mapping products to counts
    """
    product_counter = Counter()
    
    for finding in findings:
        product_counter[finding.product] += 1
    
    return dict(product_counter)


def framework_score(
    findings: list[OCSFEnrichedFinding], framework_prefix: str
) -> dict[str, int]:
    """Calculate framework compliance score.

    Args:
        findings: List of enriched findings with framework references
        framework_prefix: Framework prefix to filter by (e.g., "cis_aws_1_4")

    Returns:
        Dictionary with pass/fail/warn counts for the framework
    """
    framework_findings = []
    
    # Filter findings that belong to the specified framework
    for finding in findings:
        if hasattr(finding, 'framework_refs') and finding.framework_refs:
            for ref in finding.framework_refs:
                if ref.startswith(framework_prefix + ":"):
                    framework_findings.append(finding)
                    break
    
    # Count by status
    status_counter = Counter()
    for finding in framework_findings:
        status = finding.status or "unknown"
        status_counter[status] += 1
    
    return {
        "pass": status_counter.get("pass", 0),
        "fail": status_counter.get("fail", 0),
        "warn": status_counter.get("informational", 0) + status_counter.get("not_applicable", 0),
        "unknown": status_counter.get("unknown", 0),
        "total": len(framework_findings),
    }


def by_provider(findings: list[OCSFFinding | OCSFEnrichedFinding]) -> dict[str, dict[str, Any]]:
    """Group findings by provider with detailed breakdown.

    Args:
        findings: List of findings to analyze

    Returns:
        Dictionary mapping providers to their finding breakdowns
    """
    provider_data = defaultdict(lambda: {
        "total": 0,
        "by_severity": defaultdict(int),
        "by_status": defaultdict(int),
        "by_product": defaultdict(int),
        "unique_resources": set(),
        "unique_accounts": set(),
    })
    
    for finding in findings:
        provider = finding.provider
        data = provider_data[provider]
        
        data["total"] += 1
        data["by_severity"][finding.severity or "unknown"] += 1
        data["by_status"][finding.status or "unknown"] += 1
        data["by_product"][finding.product] += 1
        
        if finding.resource_id:
            data["unique_resources"].add(finding.resource_id)
        if finding.account_id:
            data["unique_accounts"].add(finding.account_id)
    
    # Convert sets to counts and defaultdicts to regular dicts
    result = {}
    for provider, data in provider_data.items():
        result[provider] = {
            "total": data["total"],
            "by_severity": dict(data["by_severity"]),
            "by_status": dict(data["by_status"]),
            "by_product": dict(data["by_product"]),
            "unique_resources": len(data["unique_resources"]),
            "unique_accounts": len(data["unique_accounts"]),
        }
    
    return result


def by_framework(findings: list[OCSFEnrichedFinding]) -> dict[str, dict[str, Any]]:
    """Group findings by compliance framework.

    Args:
        findings: List of enriched findings with framework references

    Returns:
        Dictionary mapping frameworks to their finding breakdowns
    """
    framework_data = defaultdict(lambda: {
        "total": 0,
        "by_severity": defaultdict(int),
        "by_status": defaultdict(int),
        "controls": set(),
        "findings": [],
    })
    
    for finding in findings:
        if hasattr(finding, 'framework_refs') and finding.framework_refs:
            for ref in finding.framework_refs:
                if ":" in ref:
                    framework, control = ref.split(":", 1)
                    data = framework_data[framework]
                    
                    data["total"] += 1
                    data["by_severity"][finding.severity or "unknown"] += 1
                    data["by_status"][finding.status or "unknown"] += 1
                    data["controls"].add(control)
                    data["findings"].append(finding)
    
    # Convert sets to counts and defaultdicts to regular dicts
    result = {}
    for framework, data in framework_data.items():
        result[framework] = {
            "total": data["total"],
            "by_severity": dict(data["by_severity"]),
            "by_status": dict(data["by_status"]),
            "controls_count": len(data["controls"]),
            "controls": sorted(data["controls"]),
            "findings": data["findings"],
        }
    
    return result


def risk_score_distribution(findings: list[OCSFEnrichedFinding]) -> dict[str, int]:
    """Calculate distribution of risk scores.

    Args:
        findings: List of enriched findings with risk scores

    Returns:
        Dictionary mapping risk score ranges to counts
    """
    score_ranges = {
        "critical (9-10)": 0,
        "high (7-8.9)": 0,
        "medium (4-6.9)": 0,
        "low (1-3.9)": 0,
        "info (0-0.9)": 0,
        "unknown": 0,
    }
    
    for finding in findings:
        if hasattr(finding, 'risk_score') and finding.risk_score is not None:
            score = finding.risk_score
            if 9 <= score <= 10:
                score_ranges["critical (9-10)"] += 1
            elif 7 <= score < 9:
                score_ranges["high (7-8.9)"] += 1
            elif 4 <= score < 7:
                score_ranges["medium (4-6.9)"] += 1
            elif 1 <= score < 4:
                score_ranges["low (1-3.9)"] += 1
            elif 0 <= score < 1:
                score_ranges["info (0-0.9)"] += 1
            else:
                score_ranges["unknown"] += 1
        else:
            score_ranges["unknown"] += 1
    
    return score_ranges


def time_range_analysis(findings: list[OCSFFinding | OCSFEnrichedFinding]) -> dict[str, datetime | None]:
    """Analyze the time range of findings.

    Args:
        findings: List of findings to analyze

    Returns:
        Dictionary with start and end timestamps
    """
    if not findings:
        return {"start": None, "end": None}
    
    timestamps = [finding.time for finding in findings if finding.time]
    
    if not timestamps:
        return {"start": None, "end": None}
    
    return {
        "start": min(timestamps),
        "end": max(timestamps),
    }


def unique_resource_analysis(findings: list[OCSFFinding | OCSFEnrichedFinding]) -> dict[str, Any]:
    """Analyze unique resources in findings.

    Args:
        findings: List of findings to analyze

    Returns:
        Dictionary with unique resource statistics
    """
    unique_resources = set()
    unique_accounts = set()
    resource_types = defaultdict(int)
    
    for finding in findings:
        if finding.resource_id:
            unique_resources.add(finding.resource_id)
            
            # Try to extract resource type from ARN or other identifiers
            resource_type = _extract_resource_type(finding.resource_id)
            if resource_type:
                resource_types[resource_type] += 1
        
        if finding.account_id:
            unique_accounts.add(finding.account_id)
    
    return {
        "unique_resources": len(unique_resources),
        "unique_accounts": len(unique_accounts),
        "resource_types": dict(resource_types),
        "resources_per_account": len(unique_resources) / max(len(unique_accounts), 1),
    }


def generate_finding_summary(
    findings: list[OCSFFinding | OCSFEnrichedFinding]
) -> FindingSummary:
    """Generate a comprehensive summary of findings.

    Args:
        findings: List of findings to summarize

    Returns:
        FindingSummary object with comprehensive statistics
    """
    # Get framework coverage if we have enriched findings
    frameworks_covered = []
    if findings and hasattr(findings[0], 'framework_refs'):
        framework_refs = set()
        for finding in findings:
            if hasattr(finding, 'framework_refs') and finding.framework_refs:
                for ref in finding.framework_refs:
                    if ":" in ref:
                        framework = ref.split(":", 1)[0]
                        framework_refs.add(framework)
        frameworks_covered = sorted(framework_refs)
    
    # Analyze time range
    time_range = time_range_analysis(findings)
    
    # Analyze unique resources
    resource_analysis = unique_resource_analysis(findings)
    
    return FindingSummary(
        total_findings=len(findings),
        by_severity=severity_counts(findings),
        by_status=status_counts(findings),
        by_provider=provider_counts(findings),
        by_product=product_counts(findings),
        frameworks_covered=frameworks_covered,
        scan_time_range=time_range,
        unique_resources=resource_analysis["unique_resources"],
        unique_accounts=resource_analysis["unique_accounts"],
    )


def _extract_resource_type(resource_id: str) -> str | None:
    """Extract resource type from resource identifier.

    Args:
        resource_id: Resource identifier (ARN, etc.)

    Returns:
        Extracted resource type or None
    """
    # Handle AWS ARNs
    if resource_id.startswith("arn:aws:"):
        parts = resource_id.split(":")
        if len(parts) >= 3:
            return parts[2]  # Service name
    
    # Handle GCP resource names
    if "googleapis.com" in resource_id:
        # Extract service from URL-like resource names
        if "//" in resource_id:
            service_part = resource_id.split("//")[1].split(".")[0]
            return service_part
    
    # Handle Azure resource IDs
    if resource_id.startswith("/subscriptions/"):
        parts = resource_id.split("/")
        if "providers" in parts:
            provider_idx = parts.index("providers")
            if provider_idx + 1 < len(parts):
                provider = parts[provider_idx + 1]
                if provider_idx + 2 < len(parts):
                    resource_type = parts[provider_idx + 2]
                    return f"{provider}/{resource_type}"
                return provider
    
    return None