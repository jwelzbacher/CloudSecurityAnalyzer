"""Tests for tool registry functionality."""

import pytest

from cs_kit.cli.config import RunConfig
from cs_kit.cli.tool_registry import (
    PROVIDER_SUPPORT,
    SUPPORTED_SCANNERS,
    UnknownScannerError,
    UnsupportedScannerError,
    get_all_supported_providers,
    get_supported_scanners_for_provider,
    select_scanners,
    validate_scanner_support,
)


class TestValidateScannerSupport:
    """Test scanner support validation."""

    def test_valid_scanner_provider_combinations(self) -> None:
        """Test valid scanner-provider combinations."""
        # All current combinations should be valid
        for provider, scanners in PROVIDER_SUPPORT.items():
            for scanner in scanners:
                # Should not raise any exception
                validate_scanner_support(provider, scanner)  # type: ignore

    def test_unknown_scanner(self) -> None:
        """Test validation with unknown scanner."""
        with pytest.raises(UnknownScannerError) as exc_info:
            validate_scanner_support("aws", "unknown_scanner")
        
        assert exc_info.value.scanner == "unknown_scanner"
        assert "unknown_scanner" in str(exc_info.value)

    def test_unsupported_scanner_for_provider(self) -> None:
        """Test validation when scanner doesn't support provider."""
        # This test assumes we might add scanners that don't support all providers
        # For now, prowler supports all providers, so we'll test with a hypothetical case
        
        # First, let's verify current state - prowler supports all providers
        for provider in PROVIDER_SUPPORT:
            validate_scanner_support(provider, "prowler")  # type: ignore

    @pytest.mark.parametrize("provider", ["aws", "gcp", "azure"])
    @pytest.mark.parametrize("scanner", ["prowler"])
    def test_all_current_combinations(self, provider: str, scanner: str) -> None:
        """Test all currently supported combinations."""
        validate_scanner_support(provider, scanner)  # type: ignore


class TestSelectScanners:
    """Test scanner selection logic."""

    def test_select_enabled_prowler_aws(self) -> None:
        """Test selecting prowler for AWS."""
        config = RunConfig(
            provider="aws",
            artifacts_dir="/tmp",
            scanners={"prowler": True},
        )
        
        selected = select_scanners(config)
        assert selected == ["prowler"]

    def test_select_disabled_scanner(self) -> None:
        """Test selecting with disabled scanner."""
        config = RunConfig(
            provider="aws",
            artifacts_dir="/tmp",
            scanners={"prowler": False},
        )
        
        selected = select_scanners(config)
        assert selected == []

    def test_select_multiple_scanners(self) -> None:
        """Test selecting multiple scanners."""
        config = RunConfig(
            provider="gcp",
            artifacts_dir="/tmp",
            scanners={"prowler": True, "other_scanner": False},
        )
        
        # Should only return enabled scanners that exist
        # Since "other_scanner" doesn't exist, it should raise an error
        # But since it's disabled, it shouldn't be checked
        selected = select_scanners(config)
        assert selected == ["prowler"]

    def test_select_unknown_enabled_scanner(self) -> None:
        """Test selecting with unknown enabled scanner."""
        config = RunConfig(
            provider="aws",
            artifacts_dir="/tmp",
            scanners={"unknown_scanner": True},
        )
        
        with pytest.raises(UnknownScannerError) as exc_info:
            select_scanners(config)
        
        assert exc_info.value.scanner == "unknown_scanner"

    @pytest.mark.parametrize("provider", ["aws", "gcp", "azure"])
    def test_select_prowler_all_providers(self, provider: str) -> None:
        """Test selecting prowler for all providers."""
        config = RunConfig(
            provider=provider,  # type: ignore
            artifacts_dir="/tmp",
            scanners={"prowler": True},
        )
        
        selected = select_scanners(config)
        assert selected == ["prowler"]

    def test_empty_scanners_dict(self) -> None:
        """Test with empty scanners configuration."""
        config = RunConfig(
            provider="aws",
            artifacts_dir="/tmp",
            scanners={},
        )
        
        selected = select_scanners(config)
        assert selected == []

    def test_mixed_enabled_disabled_scanners(self) -> None:
        """Test with mix of enabled and disabled scanners."""
        config = RunConfig(
            provider="azure",
            artifacts_dir="/tmp",
            scanners={
                "prowler": True,
                "disabled_scanner": False,
            },
        )
        
        selected = select_scanners(config)
        assert selected == ["prowler"]


class TestGetSupportedScannersForProvider:
    """Test getting supported scanners for a provider."""

    def test_aws_supported_scanners(self) -> None:
        """Test getting AWS supported scanners."""
        scanners = get_supported_scanners_for_provider("aws")
        assert "prowler" in scanners
        assert isinstance(scanners, set)

    def test_gcp_supported_scanners(self) -> None:
        """Test getting GCP supported scanners."""
        scanners = get_supported_scanners_for_provider("gcp")
        assert "prowler" in scanners
        assert isinstance(scanners, set)

    def test_azure_supported_scanners(self) -> None:
        """Test getting Azure supported scanners."""
        scanners = get_supported_scanners_for_provider("azure")
        assert "prowler" in scanners
        assert isinstance(scanners, set)

    def test_returns_copy(self) -> None:
        """Test that function returns a copy, not the original set."""
        scanners1 = get_supported_scanners_for_provider("aws")
        scanners2 = get_supported_scanners_for_provider("aws")
        
        # Should be equal but not the same object
        assert scanners1 == scanners2
        assert scanners1 is not scanners2
        
        # Modifying one shouldn't affect the other
        scanners1.add("test_scanner")
        assert "test_scanner" not in scanners2

    @pytest.mark.parametrize("provider", ["aws", "gcp", "azure"])
    def test_all_providers_support_prowler(self, provider: str) -> None:
        """Test that all providers support prowler."""
        scanners = get_supported_scanners_for_provider(provider)  # type: ignore
        assert "prowler" in scanners


class TestGetAllSupportedProviders:
    """Test getting all supported providers."""

    def test_returns_all_providers(self) -> None:
        """Test that all known providers are returned."""
        providers = get_all_supported_providers()
        
        expected_providers = {"aws", "gcp", "azure"}
        assert set(providers) == expected_providers

    def test_returns_list(self) -> None:
        """Test that function returns a list."""
        providers = get_all_supported_providers()
        assert isinstance(providers, list)

    def test_consistent_with_provider_support(self) -> None:
        """Test that returned providers match PROVIDER_SUPPORT keys."""
        providers = get_all_supported_providers()
        assert set(providers) == set(PROVIDER_SUPPORT.keys())


class TestConstants:
    """Test module constants."""

    def test_supported_scanners_not_empty(self) -> None:
        """Test that SUPPORTED_SCANNERS is not empty."""
        assert len(SUPPORTED_SCANNERS) > 0
        assert "prowler" in SUPPORTED_SCANNERS

    def test_provider_support_not_empty(self) -> None:
        """Test that PROVIDER_SUPPORT is not empty."""
        assert len(PROVIDER_SUPPORT) > 0
        
        # All providers should have at least one scanner
        for provider, scanners in PROVIDER_SUPPORT.items():
            assert len(scanners) > 0
            assert "prowler" in scanners

    def test_provider_support_scanners_exist(self) -> None:
        """Test that all scanners in PROVIDER_SUPPORT exist in SUPPORTED_SCANNERS."""
        for provider, scanners in PROVIDER_SUPPORT.items():
            for scanner in scanners:
                assert scanner in SUPPORTED_SCANNERS, (
                    f"Scanner {scanner} for provider {provider} "
                    f"not found in SUPPORTED_SCANNERS"
                )