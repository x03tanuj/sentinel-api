"""Unit tests for authorization matrix builder and visualization table rendering."""

from app.engine.auth_matrix import Outcome, build_matrix, matrix_summary, render_matrix
from app.engine.discovery import OwnedObject
from app.models import Identity


def test_build_matrix_access_rules() -> None:
    # userA owns order 101, userB owns order 202
    owned = {
        "userA": {
            "order": [OwnedObject(resource="order", object_id="101", source_endpoint="/orders")]
        },
        "userB": {
            "order": [OwnedObject(resource="order", object_id="202", source_endpoint="/orders")]
        },
    }

    identities = [
        Identity(name="userA", role="user", token="tokA"),
        Identity(name="userB", role="user", token="tokB"),
        Identity(name="admin", role="admin", token="tokAdmin"),
        Identity(name="anonymous", role="anonymous", token=None),
    ]

    cells = build_matrix(owned, identities)

    # Anonymous identity must be excluded
    assert not any(c.identity == "anonymous" for c in cells)

    # Find cell for order 101
    cell_map = {(c.identity, c.resource, c.object_id): c.expected for c in cells}

    # Order 101: userA -> ALLOW, admin -> ALLOW, userB -> DENY
    assert cell_map[("userA", "order", "101")] == Outcome.ALLOW
    assert cell_map[("admin", "order", "101")] == Outcome.ALLOW
    assert cell_map[("userB", "order", "101")] == Outcome.DENY

    # Order 202: userB -> ALLOW, admin -> ALLOW, userA -> DENY
    assert cell_map[("userB", "order", "202")] == Outcome.ALLOW
    assert cell_map[("admin", "order", "202")] == Outcome.ALLOW
    assert cell_map[("userA", "order", "202")] == Outcome.DENY


def test_matrix_summary_counts() -> None:
    owned = {
        "userA": {
            "order": [OwnedObject(resource="order", object_id="1", source_endpoint="/orders")],
            "doc": [OwnedObject(resource="doc", object_id="d1", source_endpoint="/docs")],
        },
    }
    identities = [
        Identity(name="userA", role="user", token="tokA"),
        Identity(name="userB", role="user", token="tokB"),
    ]

    cells = build_matrix(owned, identities)
    summary = matrix_summary(cells)

    assert summary["total_cells"] == 4  # 2 objects * 2 identities
    assert summary["allow_count"] == 2  # userA owns both
    assert summary["deny_count"] == 2   # userB denied on both
    assert "order" in summary["by_resource"]
    assert "doc" in summary["by_resource"]
    assert summary["by_resource"]["order"]["ALLOW"] == 1
    assert summary["by_resource"]["order"]["DENY"] == 1


def test_render_matrix_contains_columns() -> None:
    owned = {
        "userA": {
            "order": [OwnedObject(resource="order", object_id="101", source_endpoint="/orders")]
        }
    }
    identities = [
        Identity(name="userA", role="user", token="tokA"),
        Identity(name="userB", role="user", token="tokB"),
        Identity(name="admin", role="admin", token="tokAdmin"),
    ]
    cells = build_matrix(owned, identities)
    rendered = render_matrix(cells, identities)

    # Matrix table contains all identity names as column headers
    assert "userA" in rendered
    assert "userB" in rendered
    assert "admin" in rendered
    assert "order:101" in rendered
