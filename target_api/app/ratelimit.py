"""In-memory sliding window rate limiter for Target API."""

import time
from collections import defaultdict

# In-memory storage mapping client IP to list of timestamps
_login_attempts: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(
    key: str,
    max_attempts: int = 10,
    window_seconds: float = 60.0,
) -> tuple[bool, int]:
    """Check whether a client IP has exceeded the rate limit in a rolling window.

    Args:
        key: Client identifier (typically IP address).
        max_attempts: Maximum allowed requests within the time window.
        window_seconds: Rolling window duration in seconds.

    Returns:
        tuple (is_allowed, retry_after_seconds)
    """
    now = time.time()
    # Filter attempts that fall within the rolling window
    valid_attempts = [t for t in _login_attempts[key] if now - t < window_seconds]

    if len(valid_attempts) >= max_attempts:
        oldest = valid_attempts[0]
        retry_after = max(1, int(window_seconds - (now - oldest)))
        _login_attempts[key] = valid_attempts
        return False, retry_after

    valid_attempts.append(now)
    _login_attempts[key] = valid_attempts
    return True, 0


def clear_rate_limits() -> None:
    """Clear all rate limit attempt counters (helper for test reset)."""
    _login_attempts.clear()
