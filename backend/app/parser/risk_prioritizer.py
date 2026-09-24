"""Endpoint risk scoring and prioritization engine."""

from typing import Final

from app.models import Endpoint

# Module-level scoring weights documenting risk factors
SCORE_WEIGHTS: Final[dict[str, int]] = {
    "OBJECT_WRITE": 50,         # Object-level state mutations (PUT/PATCH/DELETE)
    "OBJECT_READ": 40,          # Object-level data retrieval (GET)
    "PRIVILEGED": 45,           # Administrative/internal access routes
    "POST_CREATE": 25,          # Resource creation via POST
    "REQUIRES_AUTH": 15,        # Authenticated boundary
    "HAS_BODY_SCHEMA": 10,      # Complex payload input
    "PUBLIC_UNPRIVILEGED": -30, # Genuinely public unprivileged endpoints
    "UTILITY_PATH": -100,       # Utility/system endpoints (/health, /_reset, /docs)
}

UTILITY_PREFIXES = ("/health", "/_reset", "/docs", "/openapi.json")


def is_utility_endpoint(path: str) -> bool:
    """Check if an endpoint path represents a framework or monitoring utility."""
    clean = path.strip().lower()
    return clean in UTILITY_PREFIXES or any(clean.startswith(p) for p in UTILITY_PREFIXES)


def score_endpoint(e: Endpoint) -> int:
    """Compute risk score for an endpoint based on its structural characteristics.

    Higher scores indicate higher likelihood or consequence of authorization/data flaws.
    """
    score = 0

    # 1. Utility paths penalized heavily
    if is_utility_endpoint(e.path):
        score += SCORE_WEIGHTS["UTILITY_PATH"]

    # 2. Object level mutations and reads
    if e.is_object_level:
        if e.method in ("PUT", "PATCH", "DELETE"):
            score += SCORE_WEIGHTS["OBJECT_WRITE"]
        elif e.method == "GET":
            score += SCORE_WEIGHTS["OBJECT_READ"]

    # 3. Administrative / Privileged routes
    if e.is_privileged:
        score += SCORE_WEIGHTS["PRIVILEGED"]

    # 4. Resource creation
    if e.method == "POST" and e.resource is not None:
        score += SCORE_WEIGHTS["POST_CREATE"]

    # 5. Authentication requirement
    if e.requires_auth:
        score += SCORE_WEIGHTS["REQUIRES_AUTH"]

    # 6. Body schema input presence
    if e.body_schema is not None:
        score += SCORE_WEIGHTS["HAS_BODY_SCHEMA"]

    # 7. Unauthenticated & unprivileged discount
    if not e.requires_auth and not e.is_privileged:
        score += SCORE_WEIGHTS["PUBLIC_UNPRIVILEGED"]

    return score


def prioritize(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Sort endpoints in descending order of risk score using stable ordering."""
    return sorted(endpoints, key=score_endpoint, reverse=True)
