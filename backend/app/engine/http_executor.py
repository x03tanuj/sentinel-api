"""HTTP probe execution engine with strict scope, rate, budget, and redaction controls.

All scanner HTTP traffic flows through Executor.execute to ensure safety boundaries,
rate caps, and audit guarantees are uniformly enforced across all security checks.
"""

import asyncio
from datetime import datetime, timezone
import json
import re
import shlex
import time
from typing import Any
import urllib.parse

import httpx

from app.config import Settings, assert_in_scope, get_settings
from app.engine.errors import BudgetExceededError, TargetUnreachableError
from app.engine.redaction import redact_body, redact_headers
from app.models import Identity, RequestRecord, ResponseRecord


def build_url(
    base_url: str,
    path_template: str,
    path_params: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
) -> str:
    """Safely construct a complete URL from base, template, path params, and query dict.

    Path parameter values are percent-encoded with safe='' to prevent directory traversal
    or path-manipulation attacks (e.g. '../admin' -> '..%2Fadmin').

    Args:
        base_url: Target base URL (e.g. 'http://localhost:9000').
        path_template: OpenAPI path template (e.g. '/orders/{id}').
        path_params: Dictionary of path parameter names to values.
        query: Optional dictionary of query string parameters.

    Returns:
        Formatted full URL string.

    Raises:
        ValueError: If a required path parameter placeholder is missing from path_params.
    """
    clean_base = base_url.rstrip("/")

    def _replace_param(match: re.Match) -> str:
        param_name = match.group(1)
        if not path_params or param_name not in path_params:
            raise ValueError(f"Missing required path parameter: '{param_name}'")
        raw_val = path_params[param_name]
        return urllib.parse.quote(str(raw_val), safe="")

    # Substitute {param} tokens with encoded values
    resolved_path = re.sub(r"\{([a-zA-Z0-9_]+)\}", _replace_param, path_template)
    normalized_path = "/" + resolved_path.lstrip("/")
    url = f"{clean_base}{normalized_path}"

    if query:
        qs = urllib.parse.urlencode(query, doseq=True)
        if qs:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{qs}"

    return url


def generate_curl(request: RequestRecord) -> str:
    """Generate a reproducible, copy-pasteable curl command from a RequestRecord.

    Replaces authorization tokens with $TOKEN shell variable (unquoted in double-quotes)
    so credentials are never leaked in terminal logs or vulnerability artifacts.

    Args:
        request: RequestRecord containing method, url, scrubbed headers, and body.

    Returns:
        Safe curl command string.
    """
    parts = ["curl", "-X", request.method, shlex.quote(request.url)]

    # Check if request required authentication
    has_auth = any(k.lower() == "authorization" for k in request.headers_redacted.keys())
    if has_auth:
        parts.append('-H "Authorization: Bearer $TOKEN"')

    if request.body is not None:
        parts.append("-H 'Content-Type: application/json'")
        if isinstance(request.body, (dict, list)):
            body_str = json.dumps(request.body)
        else:
            body_str = str(request.body)
        parts.append(f"-d {shlex.quote(body_str)}")

    return " ".join(parts)


class Executor:
    """Safe, rate-capped, budget-enforced HTTP execution client for API security probes."""

    def __init__(
        self,
        settings: Settings | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        """Initialize executor with configuration settings and optional mock transport.

        Args:
            settings: Optional Settings instance; uses cached settings if None.
            transport: Optional custom transport (primarily used for unit testing).
        """
        self.settings: Settings = settings or get_settings()
        self.transport = transport
        self._requests_sent: int = 0
        self._audit_log: list[dict[str, Any]] = []
        self._lock = asyncio.Lock()
        self._last_request_time: float = 0.0

        self.client = httpx.AsyncClient(
            transport=transport,
            follow_redirects=False,
            timeout=self.settings.REQUEST_TIMEOUT,
            headers={"User-Agent": "SentinelAPI-Scanner/0.1 (authorized-testing)"},
        )

    @property
    def requests_sent(self) -> int:
        """Total number of HTTP requests executed by this engine instance."""
        return self._requests_sent

    @property
    def budget_remaining(self) -> int:
        """Remaining request allowance under MAX_REQUESTS_PER_SCAN budget."""
        return max(0, self.settings.MAX_REQUESTS_PER_SCAN - self._requests_sent)

    @property
    def audit_log(self) -> list[dict[str, Any]]:
        """Audit log of executed requests containing metadata only (no headers or bodies)."""
        return list(self._audit_log)

    async def aclose(self) -> None:
        """Close underlying HTTP client connections."""
        await self.client.aclose()

    async def __aenter__(self) -> "Executor":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    async def execute(
        self,
        method: str,
        url: str,
        identity: Identity | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[RequestRecord, ResponseRecord]:
        """Execute a guarded, rate-limited HTTP probe request against a target endpoint.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.).
            url: Full target URL.
            identity: Optional test Identity; sends 'Authorization: Bearer <token>' if set.
            params: Optional query parameters dictionary.
            json_body: Optional JSON request payload.
            extra_headers: Optional additional headers.

        Returns:
            Tuple of (RequestRecord with redacted headers/body, raw in-memory ResponseRecord).

        Raises:
            ScopeViolationError: If final URL is outside the allowed target scope.
            BudgetExceededError: If the maximum request budget per scan is exceeded.
            TargetUnreachableError: If a connection or network timeout occurs.
        """
        # 1. Build final URL and validate scope BEFORE anything else
        final_url = url
        if params:
            qs = urllib.parse.urlencode(params, doseq=True)
            if qs:
                separator = "&" if "?" in final_url else "?"
                final_url = f"{final_url}{separator}{qs}"

        assert_in_scope(final_url, self.settings)

        # 2. Enforce request budget and rate cap atomically
        min_interval = 1.0 / max(1, self.settings.MAX_RPS)
        async with self._lock:
            if self._requests_sent >= self.settings.MAX_REQUESTS_PER_SCAN:
                raise BudgetExceededError(
                    f"Maximum scan request budget of {self.settings.MAX_REQUESTS_PER_SCAN} exceeded."
                )

            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_request_time = time.monotonic()
            self._requests_sent += 1

        # 3. Construct outgoing headers (token never placed anywhere else)
        out_headers = dict(extra_headers or {})
        if identity and identity.token and identity.name != "anonymous":
            out_headers["Authorization"] = f"Bearer {identity.token}"

        if json_body is not None:
            lower_keys = {k.lower() for k in out_headers.keys()}
            if "content-type" not in lower_keys:
                out_headers["Content-Type"] = "application/json"

        # 6. Stream request to cap response reading at MAX_RESPONSE_BYTES
        start_time = time.perf_counter()
        body_chunks: list[bytes] = []
        bytes_read = 0
        is_truncated = False

        try:
            async with self.client.stream(
                method=method.upper(),
                url=final_url,
                headers=out_headers,
                json=json_body if json_body is not None else None,
            ) as response:
                status_code = response.status_code
                resp_headers = dict(response.headers)

                async for chunk in response.aiter_bytes():
                    needed = self.settings.MAX_RESPONSE_BYTES - bytes_read
                    if len(chunk) > needed:
                        body_chunks.append(chunk[:needed])
                        bytes_read += needed
                        is_truncated = True
                        break
                    body_chunks.append(chunk)
                    bytes_read += len(chunk)
                    if bytes_read >= self.settings.MAX_RESPONSE_BYTES:
                        is_truncated = True
                        break

        except (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError, httpx.RequestError) as err:
            raise TargetUnreachableError(
                f"Target {method.upper()} {final_url} is unreachable: {type(err).__name__}"
            ) from None

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        if is_truncated:
            resp_headers["x-sentinel-truncated"] = "true"

        # 7. Parse response body
        raw_bytes = b"".join(body_chunks)
        content_type = resp_headers.get("content-type", "").lower()
        if "json" in content_type:
            try:
                parsed_body: Any = json.loads(raw_bytes.decode("utf-8"))
            except Exception:
                parsed_body = raw_bytes.decode("utf-8", errors="replace")
        else:
            parsed_body = raw_bytes.decode("utf-8", errors="replace")

        # 8. Append to audit log (metadata only: no headers, no bodies, capped at 5000)
        ident_name = identity.name if identity else "anonymous"
        audit_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": method.upper(),
            "url": final_url,
            "status": status_code,
            "latency_ms": round(latency_ms, 2),
            "identity": ident_name,
        }
        self._audit_log.append(audit_entry)
        if len(self._audit_log) > 5000:
            self._audit_log = self._audit_log[-5000:]

        # 9. Build records (RequestRecord scrubbed, ResponseRecord raw in memory)
        req_record = RequestRecord(
            method=method.upper(),
            url=final_url,
            headers_redacted=redact_headers(out_headers),
            body=redact_body(json_body),
        )
        resp_record = ResponseRecord(
            status=status_code,
            headers=resp_headers,
            body=parsed_body,
            size=len(raw_bytes),
            latency_ms=round(latency_ms, 2),
        )

        return req_record, resp_record
