"""Scan execution context for SentinelAPI security checks.

Maintains shared state across check executions: active endpoints, authenticated identities,
discovered object ownership, test cases, and tracked scanner-created artifacts.
"""

from dataclasses import dataclass, field
from typing import Any

from app.config import Settings
from app.engine.auth_matrix import MatrixCell
from app.engine.discovery import OwnedObject
from app.engine.http_executor import Executor
from app.engine.identity import IdentityManager
from app.engine.test_generator import TestCase
from app.models import Endpoint, Identity


@dataclass
class ScanContext:
    """Execution context passed to security check modules during a scan run."""

    base_url: str
    endpoints: list[Endpoint]
    identity_manager: IdentityManager
    owned: dict[str, dict[str, list[OwnedObject]]]
    matrix_cells: list[MatrixCell]
    cases: list[TestCase]
    executor: Executor
    settings: Settings
    sample_bodies: dict[str, dict[str, Any]] = field(default_factory=dict)
    created_objects: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def find_endpoint(
        self,
        method: str,
        resource: str | None = None,
        object_level: bool | None = None,
    ) -> Endpoint | None:
        """Find an endpoint matching the specified method, resource, and object-level criteria.

        Args:
            method: HTTP method (e.g. 'GET', 'POST', 'DELETE').
            resource: Optional resource category (e.g. 'order', 'user').
            object_level: If set, filters by is_object_level flag.

        Returns:
            Matching Endpoint instance or None.
        """
        for ep in self.endpoints:
            if ep.method.upper() != method.upper():
                continue
            if resource is not None and ep.resource != resource:
                continue
            if object_level is not None and ep.is_object_level != object_level:
                continue
            return ep
        return None

    def identity(self, name: str) -> Identity:
        """Retrieve an identity persona by name from the identity manager.

        Args:
            name: Persona name ('userA', 'admin', 'anonymous').

        Returns:
            Resolved Identity model.
        """
        return self.identity_manager.get(name)
