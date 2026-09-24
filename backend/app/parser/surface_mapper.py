"""Attack surface mapper converting OpenAPI specifications into SentinelAPI Endpoint models."""

import re
from typing import Any

from app.models import Endpoint

SUPPORTED_METHODS = {"get", "post", "put", "patch", "delete"}
IDENTIFIER_NAMES = {"id", "uuid", "guid"}
PRIVILEGED_SEGMENTS = {
    "admin",
    "internal",
    "manage",
    "management",
    "superuser",
    "root",
    "debug",
}


def infer_resource(path: str) -> str | None:
    """Infer the primary domain resource noun from an API endpoint path.

    Args:
        path: Path template string, e.g. /api/v1/orders/{id}.

    Returns:
        Singularized resource name or None for utility/system endpoints.
    """
    segments = [s.strip() for s in path.strip("/").split("/") if s.strip()]
    if not segments:
        return None

    # Utility and system endpoints return None
    first = segments[0].lower()
    if first in ("health", "_reset", "docs", "openapi.json") or first.startswith("auth"):
        return None
    if any(s.lower() in ("health", "_reset") for s in segments):
        return None

    # Find the last non-parameter segment
    non_param_segments = [s for s in segments if not (s.startswith("{") and s.endswith("}"))]
    if not non_param_segments:
        return None

    candidate = non_param_segments[-1].lower()

    # If the candidate itself is a privileged prefix (like /admin) but there is a previous or next noun
    if candidate in PRIVILEGED_SEGMENTS and len(non_param_segments) > 1:
        candidate = non_param_segments[-2].lower()

    # Simple singularization
    if candidate.endswith("sses"):
        return candidate[:-2]  # addresses -> address
    elif candidate.endswith("ies") and len(candidate) > 3:
        return candidate[:-3] + "y"  # categories -> category
    elif candidate.endswith("s") and not candidate.endswith("ss") and len(candidate) > 1:
        return candidate[:-1]  # orders -> order, users -> user

    return candidate


def is_object_level_endpoint(method: str, path: str) -> bool:
    """Determine if endpoint acts on a specific object identifier.

    True when path contains an identifier-like parameter (id, *_id, *Id, uuid, guid)
    and method is a stateful/retrieval object method (GET, PUT, PATCH, DELETE).
    """
    if method.upper() not in ("GET", "PUT", "PATCH", "DELETE"):
        return False

    params = re.findall(r"\{([^}]+)\}", path)
    for p in params:
        p_clean = p.strip()
        p_lower = p_clean.lower()
        if (
            p_lower in IDENTIFIER_NAMES
            or p_lower.endswith("_id")
            or p_clean.endswith("Id")
            or "uuid" in p_lower
            or "guid" in p_lower
        ):
            return True
    return False


def is_privileged_endpoint(path: str, tags: list[str], description: str) -> bool:
    """Determine if endpoint requires administrative or privileged capabilities."""
    segments = [s.lower().strip() for s in path.strip("/").split("/")]
    if any(s in PRIVILEGED_SEGMENTS for s in segments):
        return True

    for t in tags:
        t_lower = t.lower()
        if "admin" in t_lower or "internal" in t_lower:
            return True

    if "admin only" in description.lower():
        return True

    return False


def check_requires_auth(
    operation: dict[str, Any],
    global_security: list[dict[str, Any]] | None,
) -> bool:
    """Determine if an operation enforces authentication requirements.

    Operation-level security takes precedence. Explicit empty list [] denotes public.
    """
    if "security" in operation:
        op_sec = operation.get("security")
        if op_sec is None or op_sec == []:
            return False
        # If security list contains entries with keys, auth is required
        return any(bool(s) for s in op_sec)

    # Fall back to global security
    if global_security:
        return any(bool(s) for s in global_security)

    return False


def extract_parameters(
    path_item: dict[str, Any],
    operation: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Merge path-level and operation-level parameters and categorize by location."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}

    for p in path_item.get("parameters", []):
        if isinstance(p, dict) and "name" in p:
            merged[(p["name"], p.get("in", ""))] = p

    for p in operation.get("parameters", []):
        if isinstance(p, dict) and "name" in p:
            merged[(p["name"], p.get("in", ""))] = p

    path_params = [
        name for (name, loc) in merged.keys() if loc == "path"
    ]
    query_params = [
        name for (name, loc) in merged.keys() if loc == "query"
    ]
    return path_params, query_params


def extract_schemas(operation: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Extract requestBody and primary 2xx response JSON schemas."""
    # Body schema
    body_schema: dict[str, Any] | None = None
    req_body = operation.get("requestBody")
    if isinstance(req_body, dict):
        content = req_body.get("content", {})
        if "application/json" in content:
            body_schema = content["application/json"].get("schema")

    # Response schema
    response_schema: dict[str, Any] | None = None
    responses = operation.get("responses", {})
    if isinstance(responses, dict):
        # Look for the first 2xx response code
        success_codes = sorted([c for c in responses.keys() if str(c).startswith("2")])
        for code in success_codes:
            resp_data = responses.get(code)
            if isinstance(resp_data, dict):
                content = resp_data.get("content", {})
                if "application/json" in content and "schema" in content["application/json"]:
                    response_schema = content["application/json"]["schema"]
                    break

    return body_schema, response_schema


def build_attack_surface(spec: dict[str, Any]) -> list[Endpoint]:
    """Parse resolved OpenAPI specification into prioritized Endpoint domain models.

    Args:
        spec: Fully resolved OpenAPI 3.x specification dictionary.

    Returns:
        List of Endpoint models mapping the observable attack surface.
    """
    endpoints: list[Endpoint] = []
    paths: dict[str, Any] = spec.get("paths", {})
    global_security: list[dict[str, Any]] | None = spec.get("security")

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            method_lower = method.lower()
            if method_lower not in SUPPORTED_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            method_upper = method_lower.upper()

            # Operation ID
            operation_id = operation.get("operationId")
            if not operation_id:
                slug = re.sub(r"[^a-zA-Z0-9_]", "_", path.strip("/"))
                operation_id = f"{method_lower}_{slug}".strip("_")

            tags = [str(t) for t in operation.get("tags", [])]
            description = operation.get("description", "") or operation.get("summary", "")

            # Parameter resolution
            path_params, query_params = extract_parameters(path_item, operation)

            # Schema extraction
            body_schema, response_schema = extract_schemas(operation)

            # Security and vulnerability flags
            requires_auth = check_requires_auth(operation, global_security)
            resource = infer_resource(path)
            is_object = is_object_level_endpoint(method_upper, path)
            is_priv = is_privileged_endpoint(path, tags, description)

            endpoints.append(
                Endpoint(
                    method=method_upper,
                    path=path,
                    operation_id=operation_id,
                    requires_auth=requires_auth,
                    path_params=path_params,
                    query_params=query_params,
                    body_schema=body_schema,
                    response_schema=response_schema,
                    resource=resource,
                    is_object_level=is_object,
                    is_privileged=is_priv,
                    tags=tags,
                )
            )

    return endpoints
