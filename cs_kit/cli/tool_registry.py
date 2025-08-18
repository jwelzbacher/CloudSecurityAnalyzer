"""Tool registry for security scanners."""

from typing import Literal

from cs_kit.cli.config import RunConfig

# Supported security scanners
SUPPORTED_SCANNERS = {"prowler"}

# Provider support matrix - which scanners work with which providers
PROVIDER_SUPPORT = {
    "aws": {"prowler"},
    "gcp": {"prowler"},
    "azure": {"prowler"},
}


class UnsupportedScannerError(Exception):
    """Raised when a scanner is not supported for a provider."""

    def __init__(self, provider: str, scanner: str) -> None:
        """Initialize the error."""
        super().__init__(
            f"Scanner '{scanner}' is not supported for provider '{provider}'"
        )
        self.provider = provider
        self.scanner = scanner


class UnknownScannerError(Exception):
    """Raised when a scanner is not recognized."""

    def __init__(self, scanner: str) -> None:
        """Initialize the error."""
        super().__init__(f"Unknown scanner: '{scanner}'")
        self.scanner = scanner


def validate_scanner_support(
    provider: Literal["aws", "gcp", "azure"], scanner: str
) -> None:
    """Validate that a scanner is supported for a provider.
    
    Args:
        provider: Cloud provider
        scanner: Scanner name
        
    Raises:
        UnknownScannerError: If scanner is not recognized
        UnsupportedScannerError: If scanner doesn't support the provider
    """
    if scanner not in SUPPORTED_SCANNERS:
        raise UnknownScannerError(scanner)
    
    if scanner not in PROVIDER_SUPPORT[provider]:
        raise UnsupportedScannerError(provider, scanner)


def select_scanners(config: RunConfig) -> list[str]:
    """Select enabled scanners that are valid for the provider.
    
    Args:
        config: Run configuration
        
    Returns:
        List of enabled and supported scanner names
        
    Raises:
        UnknownScannerError: If an enabled scanner is not recognized
        UnsupportedScannerError: If an enabled scanner doesn't support the provider
    """
    enabled_scanners = [
        scanner for scanner, enabled in config.scanners.items() if enabled
    ]
    
    # Validate each enabled scanner
    for scanner in enabled_scanners:
        validate_scanner_support(config.provider, scanner)
    
    return enabled_scanners


def get_supported_scanners_for_provider(
    provider: Literal["aws", "gcp", "azure"]
) -> set[str]:
    """Get all scanners supported by a provider.
    
    Args:
        provider: Cloud provider
        
    Returns:
        Set of supported scanner names
    """
    return PROVIDER_SUPPORT[provider].copy()


def get_all_supported_providers() -> list[str]:
    """Get all supported cloud providers.
    
    Returns:
        List of provider names
    """
    return list(PROVIDER_SUPPORT.keys())