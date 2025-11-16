"""Tests for OCSF normalizer."""

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cs_kit.normalizer.ocsf_models import FindingSummary, OCSFFinding
from cs_kit.normalizer.parser import (
    _extract_account_id,
    _extract_check_id,
    _extract_description,
    _extract_region,
    _extract_remediation,
    _extract_resource_id,
    _extract_title,
    _get_nested_value,
    _normalize_severity,
    _normalize_status,
    _parse_single_finding,
    parse_ocsf,
)


class TestOCSFModels:
    """Test OCSF model classes."""

    def test_ocsf_finding_creation(self) -> None:
        """Test creating an OCSF finding."""
        finding = OCSFFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
            severity="high",
            status="fail",
            resource_id="arn:aws:iam::123456789012:root",
            account_id="123456789012",
            region="us-east-1",
            check_id="prowler-aws-iam-avoid-root-usage",
            title="Avoid the use of the root account",
            description="The root account has unrestricted access.",
            remediation="Create IAM users for daily activities.",
            raw={"test": "data"},
        )

        assert finding.provider == "aws"
        assert finding.product == "prowler"
        assert finding.severity == "high"
        assert finding.status == "fail"
        assert finding.resource_id == "arn:aws:iam::123456789012:root"
        assert finding.raw == {"test": "data"}

    def test_ocsf_finding_minimal(self) -> None:
        """Test creating a minimal OCSF finding."""
        finding = OCSFFinding(
            time=datetime.now(UTC),
            provider="gcp",
            product="prowler",
        )

        assert finding.provider == "gcp"
        assert finding.product == "prowler"
        assert finding.severity is None
        assert finding.status is None
        assert finding.raw == {}

    def test_finding_summary_creation(self) -> None:
        """Test creating a finding summary."""
        summary = FindingSummary(
            total_findings=10,
            by_severity={"high": 3, "medium": 5, "low": 2},
            by_status={"fail": 8, "pass": 2},
            by_provider={"aws": 10},
            by_product={"prowler": 10},
            frameworks_covered=["cis_aws_1_4"],
            unique_resources=5,
            unique_accounts=1,
        )

        assert summary.total_findings == 10
        assert summary.by_severity["high"] == 3
        assert summary.unique_resources == 5


class TestParseOCSF:
    """Test parse_ocsf function."""

    def test_parse_sample_file(self) -> None:
        """Test parsing the sample OCSF file."""
        sample_path = Path("tests/samples/prowler_ocsf.json")
        if not sample_path.exists():
            pytest.skip("Sample file not found")

        findings = parse_ocsf(sample_path, "aws", "prowler")

        assert len(findings) == 2
        assert all(isinstance(f, OCSFFinding) for f in findings)
        assert all(f.provider == "aws" for f in findings)
        assert all(f.product == "prowler" for f in findings)

        # Check first finding
        first_finding = findings[0]
        assert first_finding.severity == "high"
        assert first_finding.status == "fail"
        assert first_finding.check_id == "prowler-aws-iam-avoid-root-usage"
        assert "root account" in (first_finding.title or "").lower()

    def test_parse_single_object(self) -> None:
        """Test parsing a single JSON object (not array)."""
        test_data = {
            "time": "2024-01-15T10:30:00.000Z",
            "class_uid": 2001,
            "severity": "high",
            "status": "fail",
            "finding": {"uid": "test-check-id", "title": "Test Finding"},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(test_data, f)
            temp_path = Path(f.name)

        try:
            findings = parse_ocsf(temp_path, "aws", "test-tool")
            assert len(findings) == 1
            assert findings[0].check_id == "test-check-id"
            assert findings[0].title == "Test Finding"
        finally:
            temp_path.unlink()

    def test_parse_nonexistent_file(self) -> None:
        """Test parsing a nonexistent file."""
        with pytest.raises(FileNotFoundError) as exc_info:
            parse_ocsf(Path("/nonexistent/file.json"), "aws", "prowler")

        assert "OCSF file not found" in str(exc_info.value)

    def test_parse_invalid_json(self) -> None:
        """Test parsing invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content")
            temp_path = Path(f.name)

        try:
            with pytest.raises(json.JSONDecodeError):
                parse_ocsf(temp_path, "aws", "prowler")
        finally:
            temp_path.unlink()

    def test_parse_invalid_structure(self) -> None:
        """Test parsing JSON with invalid structure."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump("not an object or array", f)
            temp_path = Path(f.name)

        try:
            with pytest.raises(ValueError) as exc_info:
                parse_ocsf(temp_path, "aws", "prowler")

            assert "Expected JSON object or array" in str(exc_info.value)
        finally:
            temp_path.unlink()


class TestParseSingleFinding:
    """Test _parse_single_finding function."""

    def test_parse_complete_finding(self) -> None:
        """Test parsing a complete finding."""
        raw_finding = {
            "time": "2024-01-15T10:30:00.000Z",
            "class_uid": 2001,
            "class_name": "Security Finding",
            "severity": "high",
            "status": "fail",
            "resource": {"uid": "arn:aws:iam::123456789012:root", "region": "us-east-1"},
            "cloud": {"account": {"uid": "123456789012"}, "region": "us-east-1"},
            "finding": {
                "uid": "test-check",
                "title": "Test Finding",
                "desc": "Test description",
                "remediation": {"desc": "Fix this issue"},
            },
        }

        finding = _parse_single_finding(raw_finding, "aws", "prowler")

        assert finding.provider == "aws"
        assert finding.product == "prowler"
        assert finding.class_uid == 2001
        assert finding.class_name == "Security Finding"
        assert finding.severity == "high"
        assert finding.status == "fail"
        assert finding.resource_id == "arn:aws:iam::123456789012:root"
        assert finding.account_id == "123456789012"
        assert finding.region == "us-east-1"
        assert finding.check_id == "test-check"
        assert finding.title == "Test Finding"
        assert finding.description == "Test description"
        assert finding.remediation == "Fix this issue"
        assert finding.raw == raw_finding

    def test_parse_minimal_finding(self) -> None:
        """Test parsing a minimal finding."""
        raw_finding = {"time": "2024-01-15T10:30:00.000Z"}

        finding = _parse_single_finding(raw_finding, "gcp", "test-tool")

        assert finding.provider == "gcp"
        assert finding.product == "test-tool"
        assert finding.class_uid is None
        assert finding.severity is None
        assert finding.status is None


class TestNormalizeSeverity:
    """Test _normalize_severity function."""

    @pytest.mark.parametrize(
        "input_severity,expected",
        [
            ("critical", "critical"),
            ("CRITICAL", "critical"),
            ("crit", "critical"),
            ("high", "high"),
            ("HIGH", "high"),
            ("medium", "medium"),
            ("med", "medium"),
            ("moderate", "medium"),
            ("low", "low"),
            ("LOW", "low"),
            ("info", "informational"),
            ("informational", "informational"),
            ("information", "informational"),
            ("notice", "informational"),
            ("unknown", None),
            ("", None),
            (None, None),
        ],
    )
    def test_severity_normalization(
        self, input_severity: str | None, expected: str | None
    ) -> None:
        """Test severity normalization with various inputs."""
        result = _normalize_severity(input_severity)
        assert result == expected


class TestNormalizeStatus:
    """Test _normalize_status function."""

    @pytest.mark.parametrize(
        "input_status,expected",
        [
            ("pass", "pass"),
            ("PASS", "pass"),
            ("passed", "pass"),
            ("success", "pass"),
            ("ok", "pass"),
            ("fail", "fail"),
            ("FAIL", "fail"),
            ("failed", "fail"),
            ("failure", "fail"),
            ("error", "fail"),
            ("not_applicable", "not_applicable"),
            ("n/a", "not_applicable"),
            ("na", "not_applicable"),
            ("skip", "not_applicable"),
            ("skipped", "not_applicable"),
            ("info", "informational"),
            ("informational", "informational"),
            ("information", "informational"),
            ("unknown", None),
            ("", None),
            (None, None),
        ],
    )
    def test_status_normalization(
        self, input_status: str | None, expected: str | None
    ) -> None:
        """Test status normalization with various inputs."""
        result = _normalize_status(input_status)
        assert result == expected


class TestExtractionFunctions:
    """Test field extraction functions."""

    def test_extract_resource_id(self) -> None:
        """Test resource ID extraction from various locations."""
        test_cases = [
            ({"resource": {"uid": "test-uid"}}, "test-uid"),
            ({"resource": {"id": "test-id"}}, "test-id"),
            ({"resource_uid": "test-resource-uid"}, "test-resource-uid"),
            ({"resource_id": "test-resource-id"}, "test-resource-id"),
            ({"arn": "test-arn"}, "test-arn"),
            ({"resource_arn": "test-resource-arn"}, "test-resource-arn"),
            ({}, None),
        ]

        for raw_finding, expected in test_cases:
            result = _extract_resource_id(raw_finding)
            assert result == expected

    def test_extract_account_id(self) -> None:
        """Test account ID extraction from various locations."""
        test_cases = [
            ({"cloud": {"account": {"uid": "123456789012"}}}, "123456789012"),
            ({"cloud": {"account": {"id": "123456789012"}}}, "123456789012"),
            ({"account_uid": "123456789012"}, "123456789012"),
            ({"account_id": "123456789012"}, "123456789012"),
            ({"account": "123456789012"}, "123456789012"),
            ({}, None),
        ]

        for raw_finding, expected in test_cases:
            result = _extract_account_id(raw_finding)
            assert result == expected

    def test_extract_region(self) -> None:
        """Test region extraction from various locations."""
        test_cases = [
            ({"cloud": {"region": "us-east-1"}}, "us-east-1"),
            ({"resource": {"region": "us-west-2"}}, "us-west-2"),
            ({"region": "eu-west-1"}, "eu-west-1"),
            ({}, None),
        ]

        for raw_finding, expected in test_cases:
            result = _extract_region(raw_finding)
            assert result == expected

    def test_extract_check_id(self) -> None:
        """Test check ID extraction from various locations."""
        test_cases = [
            ({"finding": {"uid": "check-123"}}, "check-123"),
            ({"finding": {"id": "check-456"}}, "check-456"),
            ({"check_id": "check-789"}, "check-789"),
            ({"rule_id": "rule-123"}, "rule-123"),
            ({"uid": "uid-123"}, "uid-123"),
            ({"id": "id-123"}, "id-123"),
            ({}, None),
        ]

        for raw_finding, expected in test_cases:
            result = _extract_check_id(raw_finding)
            assert result == expected

    def test_extract_title(self) -> None:
        """Test title extraction from various locations."""
        test_cases = [
            ({"finding": {"title": "Test Title"}}, "Test Title"),
            ({"title": "Direct Title"}, "Direct Title"),
            ({"summary": "Summary Title"}, "Summary Title"),
            ({"name": "Name Title"}, "Name Title"),
            ({}, None),
        ]

        for raw_finding, expected in test_cases:
            result = _extract_title(raw_finding)
            assert result == expected

    def test_extract_description(self) -> None:
        """Test description extraction from various locations."""
        test_cases = [
            ({"finding": {"desc": "Test Description"}}, "Test Description"),
            ({"finding": {"description": "Full Description"}}, "Full Description"),
            ({"description": "Direct Description"}, "Direct Description"),
            ({"desc": "Short Desc"}, "Short Desc"),
            ({"message": "Message Description"}, "Message Description"),
            ({}, None),
        ]

        for raw_finding, expected in test_cases:
            result = _extract_description(raw_finding)
            assert result == expected

    def test_extract_remediation(self) -> None:
        """Test remediation extraction from various locations."""
        test_cases = [
            (
                {"finding": {"remediation": {"desc": "Fix this"}}},
                "Fix this",
            ),
            (
                {"finding": {"remediation": {"description": "Fix this too"}}},
                "Fix this too",
            ),
            ({"remediation": {"desc": "Direct fix"}}, "Direct fix"),
            ({"remediation": "Simple fix"}, "Simple fix"),
            ({"recommendation": "Recommendation"}, "Recommendation"),
            ({"fix": "Quick fix"}, "Quick fix"),
            ({}, None),
        ]

        for raw_finding, expected in test_cases:
            result = _extract_remediation(raw_finding)
            assert result == expected


class TestGetNestedValue:
    """Test _get_nested_value function."""

    def test_get_nested_value_success(self) -> None:
        """Test successful nested value extraction."""
        data = {
            "level1": {"level2": {"level3": "target_value"}},
            "simple": "simple_value",
        }

        result = _get_nested_value(data, ["level1", "level2", "level3"])
        assert result == "target_value"

        result = _get_nested_value(data, ["simple"])
        assert result == "simple_value"

    def test_get_nested_value_missing(self) -> None:
        """Test nested value extraction with missing keys."""
        data = {"level1": {"level2": "value"}}

        result = _get_nested_value(data, ["level1", "missing", "key"])
        assert result is None

        result = _get_nested_value(data, ["missing"])
        assert result is None

    def test_get_nested_value_wrong_type(self) -> None:
        """Test nested value extraction with wrong data type."""
        data = {"level1": "not_a_dict"}

        result = _get_nested_value(data, ["level1", "level2"])
        assert result is None
