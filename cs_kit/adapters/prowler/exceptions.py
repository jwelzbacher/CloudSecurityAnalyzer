"""Exceptions for Prowler adapter."""


class ProwlerError(Exception):
    """Base exception for Prowler-related errors."""

    pass


class ProwlerNotFoundError(ProwlerError):
    """Raised when Prowler CLI is not found on the system."""

    pass


class ProwlerExecutionError(ProwlerError):
    """Raised when Prowler execution fails."""

    def __init__(self, message: str, return_code: int | None = None) -> None:
        """Initialize the error.

        Args:
            message: Error message
            return_code: Process return code if available
        """
        super().__init__(message)
        self.return_code = return_code


class ProwlerOutputError(ProwlerError):
    """Raised when Prowler output is invalid or missing."""

    pass