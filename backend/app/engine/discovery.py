"""Resource discovery and object ownership mapping engine for SentinelAPI.

Discovers objects owned by each authenticated persona through legitimate API calls
(collection GET endpoints and /me endpoints) without guessing or hardcoding IDs.
"""

import logging
from typing import Any

from pydantic import BaseModel, Field

from app.engine.http_executor import Executor
from app.models import Endpoint, Identity

logger = logging.getLogger(__name__)


class OwnedObject(BaseModel):
    """Represents a discovered object resource owned by a test identity."""

    resource: str = Field(..., description="Resource category name (e.g. order, user)")
    object_id: str = Field(..., description="Discovered object identifier string")
    source_endpoint: str = Field(..., description="API endpoint path where object was discovered")
    raw: dict[str, Any] | None = Field(
        default=None,
        repr=False,
        exclude=True,
        description="Raw response dictionary kept in-memory for deep schema analysis",
    )


def extract_id(obj: dict[str, Any], resource: str | None = None) -> str | None:
    """Extract object identifier from a response dictionary.

    Checks candidates in order: 'id', '{resource}_id', 'uuid', including case variations.

    Args:
        obj: Dictionary representing an API object.
        resource: Optional resource name to derive specific id keys (e.g. 'order' -> 'order_id').

    Returns:
        String identifier if found, or None.
    """
    if not isinstance(obj, dict):
        return None

    candidates: list[str] = ["id"]
    if resource:
        clean_res = resource.strip().lower()
        candidates.append(f"{clean_res}_id")
        candidates.append(f"{clean_res}Id")
    candidates.append("uuid")

    # 1. Exact match search
    for cand in candidates:
        if cand in obj and obj[cand] is not None:
            return str(obj[cand])

    # 2. Case-insensitive fallback
    lower_map = {k.lower(): v for k, v in obj.items()}
    for cand in candidates:
        if cand.lower() in lower_map and lower_map[cand.lower()] is not None:
            return str(lower_map[cand.lower()])

    return None


async def discover_ownership(
    endpoints: list[Endpoint],
    identities: list[Identity],
    executor: Executor,
    base_url: str = "http://localhost:9000",
) -> dict[str, dict[str, list[OwnedObject]]]:
    """Discover which objects each identity owns by querying legitimate GET endpoints.

    Queries:
    1. Authenticated collection GET endpoints (no path parameters, resource defined).
    2. Self-identity endpoints ('/users/me', '/me').

    Args:
        endpoints: Attack surface endpoints mapped from OpenAPI specification.
        identities: List of authenticated identities (anonymous identity is skipped).
        executor: Guarded Executor client for sending HTTP probe requests.
        base_url: Base target API URL.

    Returns:
        Nested dictionary structure: owned[identity_name][resource] = [OwnedObject, ...]
    """
    owned: dict[str, dict[str, list[OwnedObject]]] = {}
    cap = executor.settings.DISCOVERY_MAX_REQUESTS_PER_IDENTITY

    for identity in identities:
        if identity.name == "anonymous":
            continue

        owned[identity.name] = {}

        # Pre-seed user's own identity ID if previously decoded from token claims
        if identity.user_id is not None:
            owned[identity.name]["user"] = [
                OwnedObject(
                    resource="user",
                    object_id=str(identity.user_id),
                    source_endpoint="/auth/login",
                    raw=None,
                )
            ]

        # Filter candidate discovery endpoints:
        # 1. Collection GET routes (requires_auth=True, no path params, resource set)
        # 2. Profile endpoints (/users/me, /me)
        candidates: list[Endpoint] = []
        for ep in endpoints:
            if ep.method.upper() != "GET":
                continue

            path_lower = ep.path.lower()
            op_lower = (ep.operation_id or "").lower()
            is_me_endpoint = "me" in path_lower or "me" in op_lower

            if is_me_endpoint:
                candidates.append(ep)
            elif ep.requires_auth and len(ep.path_params) == 0 and ep.resource is not None:
                candidates.append(ep)

        # Deduplicate candidates by path
        seen_paths: set[str] = set()
        deduped_candidates: list[Endpoint] = []
        for ep in candidates:
            if ep.path not in seen_paths:
                seen_paths.add(ep.path)
                deduped_candidates.append(ep)

        requests_sent = 0
        for ep in deduped_candidates:
            if requests_sent >= cap:
                logger.warning(
                    "Discovery request cap (%d) reached for identity '%s'. Skipping remaining endpoints.",
                    cap,
                    identity.name,
                )
                break

            url = f"{base_url.rstrip('/')}/{ep.path.lstrip('/')}"
            try:
                _, resp_rec = await executor.execute("GET", url, identity=identity)
                requests_sent += 1
            except Exception as exc:
                logger.debug("Discovery request failed for %s on %s: %s", identity.name, ep.path, exc)
                continue

            if resp_rec.status < 200 or resp_rec.status >= 300 or resp_rec.body is None:
                continue

            # Determine items from response body shape:
            # a) Bare list: [...]
            # b) Wrapped list: {"items": [...]}, {"data": [...]}, {"results": [...]}
            # c) Single object: {...}
            items: list[Any] = []
            if isinstance(resp_rec.body, list):
                items = resp_rec.body
            elif isinstance(resp_rec.body, dict):
                body_dict = resp_rec.body
                if "items" in body_dict and isinstance(body_dict["items"], list):
                    items = body_dict["items"]
                elif "data" in body_dict and isinstance(body_dict["data"], list):
                    items = body_dict["data"]
                elif "results" in body_dict and isinstance(body_dict["results"], list):
                    items = body_dict["results"]
                else:
                    items = [body_dict]

            # Inferred resource name
            path_lower = ep.path.lower()
            if "me" in path_lower or "me" in (ep.operation_id or "").lower():
                target_resource = "user"
            else:
                target_resource = ep.resource or "item"

            if target_resource not in owned[identity.name]:
                owned[identity.name][target_resource] = []

            for item in items:
                if not isinstance(item, dict):
                    continue

                obj_id = extract_id(item, target_resource)
                if obj_id is not None:
                    # Update identity user_id if this is a profile endpoint
                    if target_resource == "user" and identity.user_id is None:
                        identity.user_id = str(obj_id)

                    # Deduplicate within identity's resource list
                    existing_ids = {o.object_id for o in owned[identity.name][target_resource]}
                    if str(obj_id) not in existing_ids:
                        owned[identity.name][target_resource].append(
                            OwnedObject(
                                resource=target_resource,
                                object_id=str(obj_id),
                                source_endpoint=ep.path,
                                raw=item,
                            )
                        )
                else:
                    logger.debug(
                        "No discoverable identifier found in object from %s for resource %s",
                        ep.path,
                        target_resource,
                    )

    return owned


async def discover_via_creation(
    endpoints: list[Endpoint],
    identity: Identity,
    executor: Executor,
    sample_bodies: dict[str, dict[str, Any]],
    base_url: str = "http://localhost:9000",
) -> list[OwnedObject]:
    """Opt-in object discovery via resource creation (POST endpoints).

    Creates one object per resource present in sample_bodies and tracks the resulting
    identifier for authorization probing and subsequent cleanup.

    Args:
        endpoints: Attack surface endpoints.
        identity: Persona to authenticate creation requests.
        executor: Guarded Executor client.
        sample_bodies: Mapping of resource name to sample creation payload dict.
        base_url: Target base URL.

    Returns:
        List of created OwnedObject instances.
    """
    created: list[OwnedObject] = []

    for ep in endpoints:
        if ep.method.upper() != "POST" or len(ep.path_params) > 0:
            continue

        resource = ep.resource
        if not resource or resource not in sample_bodies:
            continue

        payload = sample_bodies[resource]
        url = f"{base_url.rstrip('/')}/{ep.path.lstrip('/')}"

        try:
            _, resp_rec = await executor.execute("POST", url, identity=identity, json_body=payload)
            if 200 <= resp_rec.status < 300 and isinstance(resp_rec.body, dict):
                obj_id = extract_id(resp_rec.body, resource)
                if obj_id is not None:
                    created.append(
                        OwnedObject(
                            resource=resource,
                            object_id=str(obj_id),
                            source_endpoint=ep.path,
                            raw=resp_rec.body,
                        )
                    )
        except Exception as exc:
            logger.debug("Failed creation probe for %s on %s: %s", resource, ep.path, exc)

    return created
