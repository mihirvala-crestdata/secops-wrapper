"""Custom exceptions for Google SecOps SDK."""

class SecOpsError(Exception):
    """Base exception for SecOps SDK."""
    pass

class AuthenticationError(SecOpsError):
    """Raised when authentication fails."""
    pass

class APIError(SecOpsError):
    """Raised when an API request fails."""
    pass 