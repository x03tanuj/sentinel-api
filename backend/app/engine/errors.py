"""Exception hierarchy for SentinelAPI execution and scanning engine.

All engine-specific errors subclass SentinelError to enable uniform error handling
without leaking internal tracebacks, authorization headers, or sensitive data.
"""


class SentinelError(Exception):
    """Base exception class for all SentinelAPI engine errors."""

    pass


class ScopeViolationError(SentinelError):
    """Raised when an operation or target URL violates the configured scan scope boundary."""

    pass


class BudgetExceededError(SentinelError):
    """Raised when the maximum HTTP request budget per scan run is exceeded."""

    pass


class TargetUnreachableError(SentinelError):
    """Raised when a target host or endpoint cannot be reached due to connection or network failure."""

    pass


class LoginFailedError(SentinelError):
    """Raised when authentication / login fails for an identity."""

    pass


class IdentityNotFoundError(SentinelError):
    """Raised when a requested identity is not registered or found in the manager."""

    pass
