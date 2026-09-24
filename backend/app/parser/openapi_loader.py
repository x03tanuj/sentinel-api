"""OpenAPI specification loader, validator, and schema dereferencer."""

import copy
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import prance
import yaml
from openapi_spec_validator import validate
from openapi_spec_validator.validation.exceptions import OpenAPIValidationError

from app.config import Settings, assert_in_scope, get_settings

MAX_SPEC_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB limit


class SpecLoadError(Exception):
    """Raised when an OpenAPI specification cannot be fetched or parsed."""

    pass


class SpecValidationError(Exception):
    """Raised when an OpenAPI specification fails schema conformance validation."""

    pass


def _resolve_local_refs(spec: dict[str, Any], max_depth: int = 20) -> dict[str, Any]:
    """Recursively dereference internal JSON references (#/components/...) with circular reference protection."""
    root = spec

    def _resolve(node: Any, depth: int, active_stack: set[str]) -> Any:
        if depth > max_depth:
            return {"x-circular-ref": "depth_limit_exceeded"}

        if isinstance(node, dict):
            if "$ref" in node and isinstance(node["$ref"], str):
                ref_target: str = node["$ref"]
                if ref_target.startswith("#/"):
                    ref_name = ref_target.split("/")[-1]
                    if ref_target in active_stack:
                        return {"x-circular-ref": ref_name}

                    # Navigate from root
                    parts = ref_target.lstrip("#/").split("/")
                    curr: Any = root
                    found = True
                    for p in parts:
                        if isinstance(curr, dict) and p in curr:
                            curr = curr[p]
                        else:
                            found = False
                            break

                    if found:
                        new_stack = set(active_stack)
                        new_stack.add(ref_target)
                        resolved = _resolve(curr, depth + 1, new_stack)
                        # Merge any sibling keys beside $ref if present
                        if isinstance(resolved, dict):
                            result = dict(resolved)
                            for k, v in node.items():
                                if k != "$ref":
                                    result[k] = _resolve(v, depth + 1, active_stack)
                            return result
                        return resolved
                    return {"x-unresolved-ref": ref_target}

            return {k: _resolve(v, depth + 1, active_stack) for k, v in node.items()}

        elif isinstance(node, list):
            return [_resolve(item, depth + 1, active_stack) for item in node]

        return node

    return _resolve(copy.deepcopy(spec), 0, set())


async def load_spec(
    source: str | dict[str, Any] | Path,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Load an OpenAPI specification from a dictionary, local file path, or remote URL.

    Args:
        source: Spec dictionary, local file Path/string, or target HTTP/HTTPS URL.
        settings: Application settings for scope boundaries and timeouts.

    Returns:
        Raw OpenAPI specification dictionary.

    Raises:
        SpecLoadError: If loading, downloading, or parsing fails.
        ScopeViolationError: If a remote URL target is not allow-listed.
    """
    active_settings = settings or get_settings()

    # 1. Direct dictionary
    if isinstance(source, dict):
        return copy.deepcopy(source)

    # 2. String or Path
    source_str = str(source).strip()

    # Check if URL
    parsed_url = urlparse(source_str)
    if parsed_url.scheme in ("http", "https"):
        # Enforce scope check strictly before initiating any network I/O
        assert_in_scope(source_str, settings=active_settings)

        try:
            async with httpx.AsyncClient(
                timeout=active_settings.REQUEST_TIMEOUT,
                follow_redirects=False,
            ) as client:
                response = await client.get(source_str)

                # Check Content-Length header if present
                content_len = response.headers.get("content-length")
                if content_len and int(content_len) > MAX_SPEC_SIZE_BYTES:
                    raise SpecLoadError(
                        f"Specification at {source_str} exceeds maximum allowed size of 10 MB"
                    )

                if len(response.content) > MAX_SPEC_SIZE_BYTES:
                    raise SpecLoadError(
                        f"Specification response payload exceeds maximum allowed size of 10 MB"
                    )

                if response.status_code != 200:
                    raise SpecLoadError(
                        f"Failed to fetch specification from {source_str}: HTTP {response.status_code}"
                    )

                text_content = response.text
        except httpx.RequestError as exc:
            raise SpecLoadError(f"Network error fetching specification from {source_str}: {exc}") from None

        try:
            # Try JSON first, fallback to YAML
            try:
                data = json.loads(text_content)
            except json.JSONDecodeError:
                data = yaml.safe_load(text_content)

            if not isinstance(data, dict):
                raise SpecLoadError("Loaded specification content must be a JSON/YAML object mapping.")
            return data
        except Exception as exc:
            raise SpecLoadError(f"Could not parse specification format from {source_str}: {exc}") from None

    # 3. Local file path
    file_path = Path(source_str)
    if not file_path.exists():
        raise SpecLoadError(f"Specification file not found at: {source_str}")

    try:
        file_size = file_path.stat().st_size
        if file_size > MAX_SPEC_SIZE_BYTES:
            raise SpecLoadError(f"Specification file exceeds maximum allowed size of 10 MB: {file_size} bytes")

        raw_content = file_path.read_text(encoding="utf-8")
        try:
            data = json.loads(raw_content)
        except json.JSONDecodeError:
            data = yaml.safe_load(raw_content)

        if not isinstance(data, dict):
            raise SpecLoadError(f"Specification file at {source_str} does not contain a valid mapping.")
        return data
    except SpecLoadError:
        raise
    except Exception as exc:
        raise SpecLoadError(f"Failed to read specification file {source_str}: {exc}") from None


def resolve_and_validate(spec: dict[str, Any]) -> dict[str, Any]:
    """Validate specification conformance and dereference internal schema definitions.

    Args:
        spec: Raw parsed OpenAPI specification dictionary.

    Returns:
        Validated and dereferenced OpenAPI specification dictionary.

    Raises:
        SpecValidationError: If the specification violates OpenAPI standard schemas.
    """
    # 1. Conformance Validation
    try:
        validate(spec)
    except OpenAPIValidationError as exc:
        raise SpecValidationError(f"OpenAPI schema validation failed: {exc.message}") from None
    except Exception as exc:
        raise SpecValidationError(f"Invalid OpenAPI specification structure: {exc}") from None

    # 2. Dereferencing
    try:
        parser = prance.ResolvingParser(
            spec_string=json.dumps(spec),
            lazy=False,
            strict=False,
        )
        return parser.specification
    except Exception:
        # Fallback to local circular-safe dereferencer if prance encounters issue
        return _resolve_local_refs(spec)
