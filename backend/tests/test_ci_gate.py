"""Tests for SentinelAPI CI Security Quality Gate (scripts/ci_gate.py)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

# Add scripts directory to path for unit imports
SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import ci_gate  # noqa: E402


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
VULN_FIXTURE = FIXTURES_DIR / "findings_vulnerable.json"
SECURE_FIXTURE = FIXTURES_DIR / "findings_secure.json"


def test_parse_severities_valid() -> None:
    """Test parsing valid severity lists."""
    assert ci_gate.parse_severities("CRITICAL,HIGH") == {"CRITICAL", "HIGH"}
    assert ci_gate.parse_severities("medium, low, info ") == {"MEDIUM", "LOW", "INFO"}


def test_parse_severities_invalid() -> None:
    """Test rejection of unknown severity names."""
    with pytest.raises(ValueError, match="Invalid severity level"):
        ci_gate.parse_severities("CRITICAL,ULTRA_DANGEROUS")


def test_ci_gate_fails_on_vulnerable_findings() -> None:
    """Gate returns 1 when policy-violating findings exceed thresholds."""
    exit_code = ci_gate.run_gate(
        findings_path=VULN_FIXTURE,
        fail_on={"CRITICAL", "HIGH"},
        min_confidence=0.7,
    )
    assert exit_code == 1


def test_ci_gate_passes_on_secure_findings() -> None:
    """Gate returns 0 when no findings breach severity/confidence policy."""
    exit_code = ci_gate.run_gate(
        findings_path=SECURE_FIXTURE,
        fail_on={"CRITICAL", "HIGH"},
        min_confidence=0.7,
    )
    assert exit_code == 0


def test_ci_gate_passes_when_confidence_filter_excludes() -> None:
    """Gate returns 0 when findings exist but below min_confidence threshold."""
    exit_code = ci_gate.run_gate(
        findings_path=VULN_FIXTURE,
        fail_on={"CRITICAL", "HIGH"},
        min_confidence=0.99,  # Highest vuln in fixture is 0.88
    )
    assert exit_code == 0


def test_ci_gate_passes_when_severity_filter_excludes() -> None:
    """Gate returns 0 when findings match confidence but severity is not in fail_on."""
    exit_code = ci_gate.run_gate(
        findings_path=VULN_FIXTURE,
        fail_on={"MEDIUM"},
        min_confidence=0.5,
    )
    assert exit_code == 0


def test_ci_gate_handles_empty_list(tmp_path: Path) -> None:
    """Gate handles empty findings array gracefully with code 0."""
    empty_file = tmp_path / "empty.json"
    empty_file.write_text("[]", encoding="utf-8")
    exit_code = ci_gate.run_gate(
        findings_path=empty_file,
        fail_on={"CRITICAL", "HIGH"},
        min_confidence=0.7,
    )
    assert exit_code == 0


def test_ci_gate_handles_missing_file() -> None:
    """Gate exits with error code 1 on missing file."""
    exit_code = ci_gate.run_gate(
        findings_path="/tmp/non_existent_findings_file_12345.json",
        fail_on={"CRITICAL", "HIGH"},
        min_confidence=0.7,
    )
    assert exit_code == 1


def test_ci_gate_cli_subprocess_vulnerable() -> None:
    """End-to-end CLI invocation fails on vulnerable findings fixture."""
    script_path = SCRIPTS_DIR / "ci_gate.py"
    res = subprocess.run(
        [
            sys.executable,
            str(script_path),
            "--findings",
            str(VULN_FIXTURE),
            "--fail-on",
            "CRITICAL,HIGH",
            "--min-confidence",
            "0.7",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 1
    assert "SECURITY GATE FAILED" in res.stdout
    assert "Broken Object Level Authorization" in res.stdout


def test_ci_gate_cli_subprocess_secure() -> None:
    """End-to-end CLI invocation passes on secure findings fixture."""
    script_path = SCRIPTS_DIR / "ci_gate.py"
    res = subprocess.run(
        [
            sys.executable,
            str(script_path),
            "--findings",
            str(SECURE_FIXTURE),
            "--fail-on",
            "CRITICAL,HIGH",
            "--min-confidence",
            "0.7",
        ],
        capture_output=True,
        text=True,
    )
    assert res.returncode == 0
    assert "SECURITY GATE PASSED" in res.stdout
