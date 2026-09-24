"""Authorization matrix builder and visualization renderer for SentinelAPI.

Calculates the ground-truth expectation of access rights (ALLOW vs DENY)
for every known resource object across all test personas.
"""

from enum import Enum
import io
from typing import Any

from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table

from app.engine.discovery import OwnedObject
from app.models import Identity


class Outcome(str, Enum):
    """Expected authorization outcome for a test case."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class MatrixCell(BaseModel):
    """Represents expected access outcome for an identity attempting an action on an object."""

    identity: str = Field(..., description="Probing persona identifier")
    resource: str = Field(..., description="Resource category name (e.g. order)")
    object_id: str = Field(..., description="Target object identifier")
    owner_identity: str | None = Field(default=None, description="Persona that legitimately owns the object")
    expected: Outcome = Field(..., description="Ground-truth expected authorization outcome (ALLOW or DENY)")


def build_matrix(
    owned: dict[str, dict[str, list[OwnedObject]]],
    identities: list[Identity],
) -> list[MatrixCell]:
    """Construct authorization matrix of (identity, resource, object_id) -> Outcome.

    Rules:
    1. Skip the 'anonymous' persona here (evaluated separately in unauth checks).
    2. An identity is expected to have ALLOW access if it owns the object OR has role 'admin'.
    3. Any other identity requesting the object is expected to be DENIED access.
    4. Objects appearing across multiple owners are marked as 'shared' ownership.

    Args:
        owned: Discovered ownership mapping: owned[identity_name][resource] = [OwnedObject, ...]
        identities: List of available test personas.

    Returns:
        Flat list of MatrixCell objects representing all identity-to-object authorization expectations.
    """
    # 1. Collect all known unique (resource, object_id) tuples and their owners
    object_owners: dict[tuple[str, str], list[str]] = {}
    for ident_name, res_dict in owned.items():
        for res_name, obj_list in res_dict.items():
            for obj in obj_list:
                key = (res_name, str(obj.object_id))
                if key not in object_owners:
                    object_owners[key] = []
                if ident_name not in object_owners[key]:
                    object_owners[key].append(ident_name)

    # Filter out anonymous identity from matrix rows/columns
    active_identities = [i for i in identities if i.name != "anonymous"]
    admin_names = {i.name for i in active_identities if i.role.lower() == "admin"}

    cells: list[MatrixCell] = []

    # Sort objects stably by resource, then object_id
    sorted_objects = sorted(object_owners.keys(), key=lambda x: (x[0], x[1]))

    for resource, obj_id in sorted_objects:
        owners = object_owners[(resource, obj_id)]
        owner_label = owners[0] if len(owners) == 1 else "shared"

        for ident in active_identities:
            is_owner = ident.name in owners
            is_admin = ident.name in admin_names

            expected = Outcome.ALLOW if (is_owner or is_admin) else Outcome.DENY

            cells.append(
                MatrixCell(
                    identity=ident.name,
                    resource=resource,
                    object_id=obj_id,
                    owner_identity=owner_label,
                    expected=expected,
                )
            )

    return cells


def matrix_summary(cells: list[MatrixCell]) -> dict[str, Any]:
    """Summarize expected ALLOW and DENY counts overall and broken down by resource.

    Args:
        cells: List of MatrixCell objects.

    Returns:
        Dictionary with count summaries.
    """
    allow_count = sum(1 for c in cells if c.expected == Outcome.ALLOW)
    deny_count = sum(1 for c in cells if c.expected == Outcome.DENY)

    by_resource: dict[str, dict[str, int]] = {}
    for c in cells:
        if c.resource not in by_resource:
            by_resource[c.resource] = {"ALLOW": 0, "DENY": 0}
        by_resource[c.resource][c.expected.value] += 1

    return {
        "total_cells": len(cells),
        "allow_count": allow_count,
        "deny_count": deny_count,
        "by_resource": by_resource,
    }


def render_matrix(cells: list[MatrixCell], identities: list[Identity]) -> str:
    """Render the authorization matrix as a formatted Rich table string.

    Rows represent individual discovered objects (resource:id, owner).
    Columns represent test persona identities with cells indicating:
    - 'own': Identity is legitimate owner.
    - 'admin': Identity has administrative privilege.
    - 'deny': Identity has no legitimate access.

    Args:
        cells: List of MatrixCell instances.
        identities: List of persona Identity models.

    Returns:
        Rendered rich table string.
    """
    active_identities = [i for i in identities if i.name != "anonymous"]
    if not active_identities or not cells:
        return "Authorization matrix is empty (no objects discovered)."

    table = Table(
        title="SentinelAPI Object Authorization Matrix",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("RESOURCE:ID", style="bold white", justify="left")
    table.add_column("OWNER", style="yellow", justify="left")

    for ident in active_identities:
        table.add_column(ident.name, justify="center")

    # Map cells by (resource, object_id, identity)
    cell_map: dict[tuple[str, str, str], MatrixCell] = {
        (c.resource, c.object_id, c.identity): c for c in cells
    }

    # Distinct objects
    unique_objects: dict[tuple[str, str], str] = {}
    for c in cells:
        key = (c.resource, c.object_id)
        if key not in unique_objects:
            unique_objects[key] = c.owner_identity or "unknown"

    sorted_objects = sorted(unique_objects.keys(), key=lambda x: (x[0], x[1]))

    for res, oid in sorted_objects:
        owner = unique_objects[(res, oid)]
        row = [f"{res}:{oid}", owner]

        for ident in active_identities:
            cell = cell_map.get((res, oid, ident.name))
            if not cell:
                row.append("-")
            elif ident.name == owner:
                row.append("[bold green]own[/bold green]")
            elif ident.role.lower() == "admin":
                row.append("[bold cyan]admin[/bold cyan]")
            elif cell.expected == Outcome.DENY:
                row.append("[bold red]deny[/bold red]")
            else:
                row.append("[green]allow[/green]")

        table.add_row(*row)

    # Render to string
    console = Console(file=io.StringIO(), force_terminal=False, color_system=None)
    console.print(table)
    return console.file.getvalue()
