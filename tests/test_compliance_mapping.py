"""Tests for compliance mapping functionality."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from cs_kit.normalizer.mapping import (
    ComplianceMapping,
    MappingLoadError,
    MappingNotFoundError,
    MappingRule,
    apply_mapping,
    get_framework_controls,
    get_mappings_directory,
    list_available_mappings,
    load_mapping,
    validate_mapping_file,
)
from cs_kit.normalizer.ocsf_models import OCSFFinding


class TestMappingModels:
    """Test mapping model classes."""

    def test_mapping_rule_creation(self) -> None:
        """Test creating a mapping rule."""
        rule = MappingRule(
            source="prowler:aws_iam_avoid_root_usage",
            target="CIS-1.3",
            title="Avoid root account usage",
            description="Root account should not be used",
            severity="high",
        )

        assert rule.source == "prowler:aws_iam_avoid_root_usage"
        assert rule.target == "CIS-1.3"
        assert rule.title == "Avoid root account usage"
        assert rule.severity == "high"

    def test_compliance_mapping_creation(self) -> None:
        """Test creating a compliance mapping."""
        rules = [
            MappingRule(
                source="prowler:test_check",
                target="TEST-1",
                title="Test Rule",
                description="Test description",
            )
        ]

        mapping = ComplianceMapping(
            map_id="test_mapping",
            name="Test Mapping",
            version="1.0",
            description="Test compliance mapping",
            framework_type="test",
            rules=rules,
        )

        assert mapping.map_id == "test_mapping"
        assert mapping.name == "Test Mapping"
        assert len(mapping.rules) == 1
        assert mapping.rules[0].source == "prowler:test_check"


class TestLoadMapping:
    """Test load_mapping function."""

    def test_load_existing_mapping(self) -> None:
        """Test loading an existing mapping file."""
        # This test assumes the cis_aws_1_4.yaml file exists
        try:
            mapping = load_mapping("cis_aws_1_4")
            assert mapping.map_id == "cis_aws_1_4"
            assert mapping.name == "CIS Amazon Web Services Foundations Benchmark v1.4"
            assert len(mapping.rules) > 0
            assert mapping.framework_type == "cis"
            assert mapping.provider == "aws"
        except MappingNotFoundError:
            pytest.skip("CIS AWS mapping file not found")

    def test_load_nonexistent_mapping(self) -> None:
        """Test loading a nonexistent mapping."""
        with pytest.raises(MappingNotFoundError) as exc_info:
            load_mapping("nonexistent_mapping")

        assert "not found" in str(exc_info.value)
        assert "Available mappings" in str(exc_info.value)

    def test_load_invalid_yaml(self) -> None:
        """Test loading invalid YAML file."""
        # Create temporary invalid YAML file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, dir=get_mappings_directory()
        ) as f:
            f.write("invalid: yaml: content: [")
            temp_file = Path(f.name)

        try:
            with pytest.raises(MappingLoadError) as exc_info:
                load_mapping(temp_file.stem)

            assert "Error parsing YAML" in str(exc_info.value)
        finally:
            temp_file.unlink()

    def test_load_invalid_structure(self) -> None:
        """Test loading YAML with invalid structure."""
        # Create temporary file with invalid structure
        invalid_data = {
            "map_id": "test",
            # Missing required fields
        }

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False, dir=get_mappings_directory()
        ) as f:
            yaml.dump(invalid_data, f)
            temp_file = Path(f.name)

        try:
            with pytest.raises(MappingLoadError) as exc_info:
                load_mapping(temp_file.stem)

            assert "Error loading mapping" in str(exc_info.value)
        finally:
            temp_file.unlink()


class TestListAvailableMappings:
    """Test list_available_mappings function."""

    def test_list_mappings(self) -> None:
        """Test listing available mappings."""
        mappings = list_available_mappings()
        assert isinstance(mappings, list)

        # Should include our test mappings if they exist
        expected_mappings = ["cis_aws_1_4", "nist_csf"]
        for expected in expected_mappings:
            if (get_mappings_directory() / f"{expected}.yaml").exists():
                assert expected in mappings

    def test_list_mappings_empty_directory(self) -> None:
        """Test listing mappings from empty directory."""
        # This is hard to test without mocking, but we can at least
        # ensure the function doesn't crash
        mappings = list_available_mappings()
        assert isinstance(mappings, list)


class TestApplyMapping:
    """Test apply_mapping function."""

    def test_apply_single_mapping(self) -> None:
        """Test applying a single mapping to findings."""
        # Create test finding
        finding = OCSFFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
            check_id="aws_iam_avoid_root_usage",
            title="Root account usage detected",
            severity="high",
            status="fail",
        )

        try:
            enriched_findings = apply_mapping([finding], ["cis_aws_1_4"])
            assert len(enriched_findings) == 1

            enriched = enriched_findings[0]
            assert len(enriched.framework_refs) > 0
            assert any("cis_aws_1_4" in ref for ref in enriched.framework_refs)
        except MappingNotFoundError:
            pytest.skip("CIS AWS mapping file not found")

    def test_apply_multiple_mappings(self) -> None:
        """Test applying multiple mappings to findings."""
        finding = OCSFFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
            check_id="aws_iam_avoid_root_usage",
            title="Root account usage detected",
        )

        try:
            enriched_findings = apply_mapping([finding], ["cis_aws_1_4", "nist_csf"])
            assert len(enriched_findings) == 1

            enriched = enriched_findings[0]
            # Should have references from both frameworks
            framework_names = {ref.split(":")[0] for ref in enriched.framework_refs}
            expected_frameworks = {"cis_aws_1_4", "nist_csf"}
            assert framework_names.intersection(expected_frameworks)
        except MappingNotFoundError:
            pytest.skip("Mapping files not found")

    def test_apply_mapping_no_matches(self) -> None:
        """Test applying mapping with no matching rules."""
        finding = OCSFFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
            check_id="nonexistent_check",
            title="Unknown check",
        )

        try:
            enriched_findings = apply_mapping([finding], ["cis_aws_1_4"])
            assert len(enriched_findings) == 1

            enriched = enriched_findings[0]
            assert len(enriched.framework_refs) == 0
        except MappingNotFoundError:
            pytest.skip("CIS AWS mapping file not found")

    def test_apply_mapping_empty_findings(self) -> None:
        """Test applying mapping to empty findings list."""
        try:
            enriched_findings = apply_mapping([], ["cis_aws_1_4"])
            assert len(enriched_findings) == 0
        except MappingNotFoundError:
            pytest.skip("CIS AWS mapping file not found")

    def test_apply_mapping_empty_map_ids(self) -> None:
        """Test applying empty mapping list."""
        finding = OCSFFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
            check_id="aws_iam_avoid_root_usage",
        )

        enriched_findings = apply_mapping([finding], [])
        assert len(enriched_findings) == 1
        assert len(enriched_findings[0].framework_refs) == 0

    def test_apply_mapping_nonexistent_mapping(self) -> None:
        """Test applying nonexistent mapping."""
        finding = OCSFFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
        )

        with pytest.raises(MappingNotFoundError):
            apply_mapping([finding], ["nonexistent_mapping"])

    def test_severity_override(self) -> None:
        """Test that mapping can override severity."""
        # Create finding without severity
        finding = OCSFFinding(
            time=datetime.now(UTC),
            provider="aws",
            product="prowler",
            check_id="aws_iam_avoid_root_usage",
            severity=None,  # No original severity
        )

        try:
            enriched_findings = apply_mapping([finding], ["cis_aws_1_4"])
            enriched = enriched_findings[0]

            # Should have severity from mapping rule
            assert enriched.severity is not None
        except MappingNotFoundError:
            pytest.skip("CIS AWS mapping file not found")


class TestGetFrameworkControls:
    """Test get_framework_controls function."""

    def test_get_controls_with_categories(self) -> None:
        """Test getting controls organized by categories."""
        try:
            controls = get_framework_controls("cis_aws_1_4")
            assert isinstance(controls, dict)
            assert len(controls) > 0

            # Should have category names as keys
            for category_name, control_list in controls.items():
                assert isinstance(category_name, str)
                assert isinstance(control_list, list)
        except MappingNotFoundError:
            pytest.skip("CIS AWS mapping file not found")

    def test_get_controls_nonexistent_mapping(self) -> None:
        """Test getting controls for nonexistent mapping."""
        with pytest.raises(MappingNotFoundError):
            get_framework_controls("nonexistent_mapping")


class TestValidateMappingFile:
    """Test validate_mapping_file function."""

    def test_validate_valid_file(self) -> None:
        """Test validating a valid mapping file."""
        mapping_file = get_mappings_directory() / "cis_aws_1_4.yaml"
        if mapping_file.exists():
            is_valid, errors = validate_mapping_file(mapping_file)
            assert is_valid
            assert len(errors) == 0
        else:
            pytest.skip("CIS AWS mapping file not found")

    def test_validate_nonexistent_file(self) -> None:
        """Test validating nonexistent file."""
        nonexistent_file = Path("/nonexistent/file.yaml")
        is_valid, errors = validate_mapping_file(nonexistent_file)

        assert not is_valid
        assert len(errors) == 1
        assert "does not exist" in errors[0]

    def test_validate_invalid_yaml(self) -> None:
        """Test validating invalid YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: [")
            temp_file = Path(f.name)

        try:
            is_valid, errors = validate_mapping_file(temp_file)
            assert not is_valid
            assert len(errors) > 0
            assert any("YAML parsing error" in error for error in errors)
        finally:
            temp_file.unlink()

    def test_validate_invalid_structure(self) -> None:
        """Test validating file with invalid structure."""
        invalid_data = {"invalid": "structure"}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(invalid_data, f)
            temp_file = Path(f.name)

        try:
            is_valid, errors = validate_mapping_file(temp_file)
            assert not is_valid
            assert len(errors) > 0
            assert any("Validation error" in error for error in errors)
        finally:
            temp_file.unlink()


class TestGetMappingsDirectory:
    """Test get_mappings_directory function."""

    def test_get_mappings_directory(self) -> None:
        """Test getting mappings directory."""
        mappings_dir = get_mappings_directory()
        assert isinstance(mappings_dir, Path)
        assert mappings_dir.name == "mappings"

        # Should be relative to the cs_kit package
        assert "cs_kit" in str(mappings_dir)
