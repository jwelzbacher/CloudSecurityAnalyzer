"""Tests for findings summarization functionality."""

from datetime import UTC, datetime

from cs_kit.normalizer.ocsf_models import OCSFEnrichedFinding, OCSFFinding
from cs_kit.normalizer.summarize import (
    _extract_resource_type,
    by_framework,
    by_provider,
    framework_score,
    generate_finding_summary,
    product_counts,
    provider_counts,
    risk_score_distribution,
    severity_counts,
    status_counts,
    time_range_analysis,
    unique_resource_analysis,
)


class TestSeverityCounts:
    """Test severity_counts function."""

    def test_severity_counts_basic(self) -> None:
        """Test basic severity counting."""
        findings = [
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity="high",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity="medium",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity="high",
            ),
        ]

        counts = severity_counts(findings)
        assert counts["high"] == 2
        assert counts["medium"] == 1
        assert len(counts) == 2

    def test_severity_counts_with_none(self) -> None:
        """Test severity counting with None values."""
        findings = [
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity="high",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity=None,
            ),
        ]

        counts = severity_counts(findings)
        assert counts["high"] == 1
        assert counts["unknown"] == 1

    def test_severity_counts_empty(self) -> None:
        """Test severity counting with empty list."""
        counts = severity_counts([])
        assert counts == {}


class TestStatusCounts:
    """Test status_counts function."""

    def test_status_counts_basic(self) -> None:
        """Test basic status counting."""
        findings = [
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                status="fail",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                status="pass",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                status="fail",
            ),
        ]

        counts = status_counts(findings)
        assert counts["fail"] == 2
        assert counts["pass"] == 1

    def test_status_counts_with_none(self) -> None:
        """Test status counting with None values."""
        findings = [
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                status="pass",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                status=None,
            ),
        ]

        counts = status_counts(findings)
        assert counts["pass"] == 1
        assert counts["unknown"] == 1


class TestProviderCounts:
    """Test provider_counts function."""

    def test_provider_counts_basic(self) -> None:
        """Test basic provider counting."""
        findings = [
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="gcp",
                product="prowler",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
            ),
        ]

        counts = provider_counts(findings)
        assert counts["aws"] == 2
        assert counts["gcp"] == 1


class TestProductCounts:
    """Test product_counts function."""

    def test_product_counts_basic(self) -> None:
        """Test basic product counting."""
        findings = [
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="scout",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
            ),
        ]

        counts = product_counts(findings)
        assert counts["prowler"] == 2
        assert counts["scout"] == 1


class TestFrameworkScore:
    """Test framework_score function."""

    def test_framework_score_basic(self) -> None:
        """Test basic framework scoring."""
        findings = [
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                status="fail",
                framework_refs=["cis_aws_1_4:CIS-1.3"],
            ),
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                status="pass",
                framework_refs=["cis_aws_1_4:CIS-1.4"],
            ),
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                status="informational",
                framework_refs=["cis_aws_1_4:CIS-1.5"],
            ),
        ]

        score = framework_score(findings, "cis_aws_1_4")
        assert score["fail"] == 1
        assert score["pass"] == 1
        assert score["warn"] == 1
        assert score["total"] == 3

    def test_framework_score_no_matches(self) -> None:
        """Test framework scoring with no matching findings."""
        findings = [
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                status="fail",
                framework_refs=["nist_csf:PR.AC-1"],
            ),
        ]

        score = framework_score(findings, "cis_aws_1_4")
        assert score["total"] == 0
        assert score["fail"] == 0
        assert score["pass"] == 0

    def test_framework_score_empty(self) -> None:
        """Test framework scoring with empty findings."""
        score = framework_score([], "cis_aws_1_4")
        assert score["total"] == 0


class TestByProvider:
    """Test by_provider function."""

    def test_by_provider_basic(self) -> None:
        """Test basic provider breakdown."""
        findings = [
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity="high",
                status="fail",
                resource_id="arn:aws:iam::123456789012:root",
                account_id="123456789012",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="scout",
                severity="medium",
                status="pass",
                resource_id="arn:aws:s3:::bucket",
                account_id="123456789012",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="gcp",
                product="prowler",
                severity="low",
                status="fail",
                resource_id="projects/test-project/instances/test-instance",
                account_id="test-project",
            ),
        ]

        breakdown = by_provider(findings)

        assert "aws" in breakdown
        assert "gcp" in breakdown

        aws_data = breakdown["aws"]
        assert aws_data["total"] == 2
        assert aws_data["by_severity"]["high"] == 1
        assert aws_data["by_severity"]["medium"] == 1
        assert aws_data["by_status"]["fail"] == 1
        assert aws_data["by_status"]["pass"] == 1
        assert aws_data["by_product"]["prowler"] == 1
        assert aws_data["by_product"]["scout"] == 1
        assert aws_data["unique_resources"] == 2
        assert aws_data["unique_accounts"] == 1

        gcp_data = breakdown["gcp"]
        assert gcp_data["total"] == 1
        assert gcp_data["unique_resources"] == 1
        assert gcp_data["unique_accounts"] == 1


class TestByFramework:
    """Test by_framework function."""

    def test_by_framework_basic(self) -> None:
        """Test basic framework breakdown."""
        findings = [
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity="high",
                status="fail",
                framework_refs=["cis_aws_1_4:CIS-1.3", "nist_csf:PR.AC-1"],
            ),
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity="medium",
                status="pass",
                framework_refs=["cis_aws_1_4:CIS-1.4"],
            ),
        ]

        breakdown = by_framework(findings)

        assert "cis_aws_1_4" in breakdown
        assert "nist_csf" in breakdown

        cis_data = breakdown["cis_aws_1_4"]
        assert cis_data["total"] == 2  # First finding counted twice due to multiple refs
        assert cis_data["controls_count"] == 2
        assert "CIS-1.3" in cis_data["controls"]
        assert "CIS-1.4" in cis_data["controls"]

        nist_data = breakdown["nist_csf"]
        assert nist_data["total"] == 1
        assert nist_data["controls_count"] == 1
        assert "PR.AC-1" in nist_data["controls"]


class TestRiskScoreDistribution:
    """Test risk_score_distribution function."""

    def test_risk_score_distribution_basic(self) -> None:
        """Test basic risk score distribution."""
        findings = [
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                risk_score=9.5,
            ),
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                risk_score=7.2,
            ),
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                risk_score=5.0,
            ),
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                risk_score=2.1,
            ),
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                risk_score=0.5,
            ),
        ]

        distribution = risk_score_distribution(findings)
        assert distribution["critical (9-10)"] == 1
        assert distribution["high (7-8.9)"] == 1
        assert distribution["medium (4-6.9)"] == 1
        assert distribution["low (1-3.9)"] == 1
        assert distribution["info (0-0.9)"] == 1
        assert distribution["unknown"] == 0

    def test_risk_score_distribution_with_unknown(self) -> None:
        """Test risk score distribution with unknown scores."""
        findings = [
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                risk_score=None,
            ),
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                # No risk_score attribute
            ),
        ]

        distribution = risk_score_distribution(findings)
        assert distribution["unknown"] == 2


class TestTimeRangeAnalysis:
    """Test time_range_analysis function."""

    def test_time_range_analysis_basic(self) -> None:
        """Test basic time range analysis."""
        time1 = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
        time2 = datetime(2024, 1, 15, 11, 0, 0, tzinfo=UTC)
        time3 = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)

        findings = [
            OCSFFinding(
                time=time2,
                provider="aws",
                product="prowler",
            ),
            OCSFFinding(
                time=time1,
                provider="aws",
                product="prowler",
            ),
            OCSFFinding(
                time=time3,
                provider="aws",
                product="prowler",
            ),
        ]

        time_range = time_range_analysis(findings)
        assert time_range["start"] == time1
        assert time_range["end"] == time3

    def test_time_range_analysis_empty(self) -> None:
        """Test time range analysis with empty findings."""
        time_range = time_range_analysis([])
        assert time_range["start"] is None
        assert time_range["end"] is None


class TestUniqueResourceAnalysis:
    """Test unique_resource_analysis function."""

    def test_unique_resource_analysis_basic(self) -> None:
        """Test basic unique resource analysis."""
        findings = [
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                resource_id="arn:aws:iam::123456789012:root",
                account_id="123456789012",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                resource_id="arn:aws:s3:::bucket",
                account_id="123456789012",
            ),
            OCSFFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                resource_id="arn:aws:iam::123456789012:root",  # Duplicate
                account_id="987654321098",  # Different account
            ),
        ]

        analysis = unique_resource_analysis(findings)
        assert analysis["unique_resources"] == 2
        assert analysis["unique_accounts"] == 2
        assert "iam" in analysis["resource_types"]
        assert "s3" in analysis["resource_types"]
        assert analysis["resources_per_account"] == 1.0


class TestGenerateFindingSummary:
    """Test generate_finding_summary function."""

    def test_generate_finding_summary_basic(self) -> None:
        """Test basic finding summary generation."""
        findings = [
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="aws",
                product="prowler",
                severity="high",
                status="fail",
                resource_id="arn:aws:iam::123456789012:root",
                account_id="123456789012",
                framework_refs=["cis_aws_1_4:CIS-1.3"],
            ),
            OCSFEnrichedFinding(
                time=datetime.now(UTC),
                provider="gcp",
                product="prowler",
                severity="medium",
                status="pass",
                resource_id="projects/test/instances/test",
                account_id="test-project",
                framework_refs=["nist_csf:PR.AC-1"],
            ),
        ]

        summary = generate_finding_summary(findings)

        assert summary.total_findings == 2
        assert summary.by_severity["high"] == 1
        assert summary.by_severity["medium"] == 1
        assert summary.by_status["fail"] == 1
        assert summary.by_status["pass"] == 1
        assert summary.by_provider["aws"] == 1
        assert summary.by_provider["gcp"] == 1
        assert summary.by_product["prowler"] == 2
        assert "cis_aws_1_4" in summary.frameworks_covered
        assert "nist_csf" in summary.frameworks_covered
        assert summary.unique_resources == 2
        assert summary.unique_accounts == 2

    def test_generate_finding_summary_empty(self) -> None:
        """Test finding summary generation with empty list."""
        summary = generate_finding_summary([])

        assert summary.total_findings == 0
        assert summary.by_severity == {}
        assert summary.frameworks_covered == []
        assert summary.unique_resources == 0
        assert summary.unique_accounts == 0


class TestExtractResourceType:
    """Test _extract_resource_type function."""

    def test_extract_resource_type_aws_arn(self) -> None:
        """Test extracting resource type from AWS ARN."""
        test_cases = [
            ("arn:aws:iam::123456789012:root", "iam"),
            ("arn:aws:s3:::my-bucket", "s3"),
            ("arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0", "ec2"),
            ("arn:aws:rds:us-east-1:123456789012:db:mydb", "rds"),
        ]

        for arn, expected_type in test_cases:
            result = _extract_resource_type(arn)
            assert result == expected_type

    def test_extract_resource_type_gcp(self) -> None:
        """Test extracting resource type from GCP resource names."""
        test_cases = [
            ("//compute.googleapis.com/projects/test/zones/us-central1-a/instances/test", "compute"),
            ("//storage.googleapis.com/projects/test/buckets/test-bucket", "storage"),
        ]

        for resource_name, expected_type in test_cases:
            result = _extract_resource_type(resource_name)
            assert result == expected_type

    def test_extract_resource_type_azure(self) -> None:
        """Test extracting resource type from Azure resource IDs."""
        test_cases = [
            (
                "/subscriptions/12345/resourceGroups/test/providers/Microsoft.Compute/virtualMachines/test-vm",
                "Microsoft.Compute/virtualMachines",
            ),
            (
                "/subscriptions/12345/resourceGroups/test/providers/Microsoft.Storage/storageAccounts/test",
                "Microsoft.Storage/storageAccounts",
            ),
        ]

        for resource_id, expected_type in test_cases:
            result = _extract_resource_type(resource_id)
            assert result == expected_type

    def test_extract_resource_type_unknown(self) -> None:
        """Test extracting resource type from unknown format."""
        unknown_formats = [
            "unknown-format",
            "not-a-resource-id",
            "",
        ]

        for unknown_format in unknown_formats:
            result = _extract_resource_type(unknown_format)
            assert result is None
