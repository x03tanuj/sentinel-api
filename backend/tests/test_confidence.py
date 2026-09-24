"""Unit tests for confidence scoring and empirical reproduction refinement."""

import pytest

from app.engine.risk import compute_confidence


def test_confidence_reproduced_increases_over_base() -> None:
    """reproduced=True with reproduction_count=2 must increase confidence over base."""
    base = 0.80
    conf_reproduced_1 = compute_confidence(reproduced=True, reproduction_count=1, base_confidence=base)
    assert conf_reproduced_1 == 0.85
    assert conf_reproduced_1 > base

    conf_reproduced_2 = compute_confidence(reproduced=True, reproduction_count=2, base_confidence=base)
    assert conf_reproduced_2 == 0.88
    assert conf_reproduced_2 > conf_reproduced_1


def test_confidence_not_reproduced_drops_by_point_two() -> None:
    """reproduced=False drops confidence by exactly 0.20 (clamped at 0.0)."""
    base = 0.85
    conf_failed = compute_confidence(reproduced=False, reproduction_count=0, base_confidence=base)
    assert round(conf_failed, 2) == 0.65
    assert round(base - conf_failed, 2) == 0.20

    base_low = 0.10
    conf_clamped = compute_confidence(reproduced=False, reproduction_count=0, base_confidence=base_low)
    assert conf_clamped == 0.0


def test_confidence_bounds_clamping() -> None:
    """Confidence score must never exceed 1.0 or drop below 0.0."""
    conf_high = compute_confidence(reproduced=True, reproduction_count=5, base_confidence=0.98)
    assert conf_high == 1.0
    assert 0.0 <= conf_high <= 1.0

    conf_low = compute_confidence(reproduced=False, reproduction_count=0, base_confidence=0.05)
    assert conf_low == 0.0
    assert 0.0 <= conf_low <= 1.0
