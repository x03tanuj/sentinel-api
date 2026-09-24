"""Target API placeholder demo service for SentinelAPI security scanner testing."""

from fastapi import FastAPI

app = FastAPI(
    title="Target API (Vulnerable Demo Placeholder)",
    description="Deliberately vulnerable API sandbox used as test target for SentinelAPI.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    """Healthcheck endpoint for target_api service."""
    return {"status": "ok", "service": "target_api"}
