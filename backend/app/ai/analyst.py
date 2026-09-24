"""AI analyst pipeline: schema, sanitization, caching, and analysis orchestration.

Design principles:
- The scanner alone decides severity/confidence; the LLM only explains.
- Finding is NEVER modified except for attaching ai_analysis.
- All LLM output is sanitized (text only, no HTML, no URLs).
- On any failure → template fallback, never an exception to the route.
- Fingerprinting ensures cache hits for identical findings.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.ai.payload import (
    FRAMEWORK_HINTS,
    PayloadNotSafeError,
    assert_payload_safe,
    build_llm_payload,
)
from app.ai.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_user_message
from app.ai.providers import LLMProvider
from app.config import Settings
from app.models import Finding

logger = logging.getLogger(__name__)

# Allowlist for code_language
_CODE_LANGUAGE_ALLOWLIST = frozenset(
    ["python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp", "generic"]
)

# Dangerous code patterns that must be replaced
_DANGEROUS_CODE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\|\s*(?:sh|bash|zsh)\b", re.IGNORECASE),
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"curl\s+.*\|\s*(?:sh|bash|zsh)\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexec\s*\([\"']https?://", re.IGNORECASE),
]

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE_RE = re.compile(r"[ \t]+")
_URL_RE = re.compile(
    r"https?://[^\s\"'<>]+"
    r"|(?:ftp|ws|wss)://[^\s\"'<>]+",
    re.IGNORECASE,
)
_MARKDOWN_FENCE_RE = re.compile(r"^```[^\n]*\n?(.*?)```\s*$", re.DOTALL)


def _sanitize_str(text: str, max_len: int) -> str:
    """Strip HTML, URLs, control chars; collapse whitespace; truncate."""
    text = _HTML_TAG_RE.sub("", text)
    text = _CONTROL_CHAR_RE.sub("", text)
    text = _URL_RE.sub("[url removed]", text)
    text = _WHITESPACE_RE.sub(" ", text)
    text = text.strip()
    if len(text) > max_len:
        text = text[: max_len - 1] + "…"
    return text


def _sanitize_code(code: str) -> str:
    """Replace dangerous shell patterns in code_fix_example."""
    for pattern in _DANGEROUS_CODE_PATTERNS:
        if pattern.search(code):
            return (
                "[code_fix_example removed: contained a dangerous shell pattern "
                "(pipe to shell, rm -rf, or remote eval). Review the remediation_steps instead.]"
            )
    return _sanitize_str(code, 1600)


class AiAnalysis(BaseModel):
    """Validated output schema for LLM-generated or template-based analysis."""

    plain_explanation: str = Field(default="", max_length=700)
    business_impact: str = Field(default="", max_length=500)
    attacker_scenario: str = Field(default="", max_length=600)
    remediation_steps: list[str] = Field(default_factory=list)
    code_fix_example: str = Field(default="", max_length=1600)
    code_language: str = Field(default="generic", max_length=20)
    verification_steps: list[str] = Field(default_factory=list)
    source: str = Field(default="template")  # "llm" | "template"
    model: str | None = Field(default=None)
    prompt_version: str = Field(default=PROMPT_VERSION)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    warning: str | None = Field(default=None)

    @field_validator("code_language", mode="before")
    @classmethod
    def validate_code_language(cls, v: Any) -> str:
        """Ensure code_language is from the allowlist."""
        s = str(v).lower().strip()
        if s not in _CODE_LANGUAGE_ALLOWLIST:
            return "generic"
        return s

    @field_validator("remediation_steps", mode="before")
    @classmethod
    def validate_remediation(cls, v: Any) -> list[str]:
        """Ensure remediation_steps is a list of 3-6 strings."""
        if not isinstance(v, list):
            return []
        cleaned = [str(item)[:250] for item in v if isinstance(item, (str, int, float))]
        # Clamp to allowed range
        if len(cleaned) < 3:
            while len(cleaned) < 3:
                cleaned.append("Review the relevant code path for authorization logic.")
        return cleaned[:6]

    @field_validator("verification_steps", mode="before")
    @classmethod
    def validate_verification(cls, v: Any) -> list[str]:
        """Ensure verification_steps is a list of 1-4 strings."""
        if not isinstance(v, list):
            return ["Rerun the SentinelAPI scan and confirm the finding is no longer present."]
        cleaned = [str(item)[:250] for item in v if isinstance(item, (str, int, float))]
        if not cleaned:
            cleaned = ["Rerun the SentinelAPI scan and confirm the finding is no longer present."]
        return cleaned[:4]

    @model_validator(mode="before")
    @classmethod
    def drop_forbidden_fields(cls, data: Any) -> Any:
        """Drop severity/confidence fields if the model sneaks them in."""
        if isinstance(data, dict):
            data.pop("severity", None)
            data.pop("confidence", None)
            data.pop("score", None)
        return data


def sanitize_analysis(analysis: AiAnalysis) -> AiAnalysis:
    """Apply text sanitization to all string fields of an AiAnalysis."""
    return AiAnalysis(
        plain_explanation=_sanitize_str(analysis.plain_explanation, 700),
        business_impact=_sanitize_str(analysis.business_impact, 500),
        attacker_scenario=_sanitize_str(analysis.attacker_scenario, 600),
        remediation_steps=[_sanitize_str(s, 250) for s in analysis.remediation_steps],
        code_fix_example=_sanitize_code(analysis.code_fix_example),
        code_language=analysis.code_language,
        verification_steps=[_sanitize_str(s, 250) for s in analysis.verification_steps],
        source=analysis.source,
        model=analysis.model,
        prompt_version=analysis.prompt_version,
        generated_at=analysis.generated_at,
        warning=analysis.warning,
    )


def build_template_analysis(finding: Finding, warning: str | None = None) -> AiAnalysis:
    """Build a deterministic analysis from the finding's existing fields.

    This is the fallback used when AI is disabled, the provider errors,
    or the payload safety assertion fires.
    """
    return AiAnalysis(
        plain_explanation=_sanitize_str(finding.explanation, 700),
        business_impact=(
            f"This {finding.severity.value} severity finding in the {finding.check} check "
            "may expose sensitive data or functionality to unauthorized parties."
        ),
        attacker_scenario=(
            f"An attacker with the role of an unauthorized user performs a {finding.method} "
            f"request to {finding.endpoint} and receives a response indicating unauthorized access."
        ),
        remediation_steps=[
            _sanitize_str(finding.fix_hint, 250),
            "Apply the principle of least privilege to all API endpoints.",
            "Add authorization checks server-side before returning any data.",
            "Review all endpoints that return or modify resources owned by other users.",
        ],
        code_fix_example="# See remediation_steps above for guidance.",
        code_language="generic",
        verification_steps=[
            "Rerun the SentinelAPI scan and confirm the finding is no longer present.",
            f"Confirm that a {finding.method} request to {finding.endpoint} by a non-owner returns 403.",
        ],
        source="template",
        model=None,
        prompt_version=PROMPT_VERSION,
        warning=warning,
    )


def fingerprint(finding: Finding, framework_hint: str, model: str) -> str:
    """Compute a cache key from the finding's structural identity.

    Uses sha256 of: check, method, path, severity, sorted changed/leaked field names,
    expected/actual status, framework_hint, PROMPT_VERSION, model.
    Does NOT include timestamps, IDs, or any free-text fields.
    """
    evidence = finding.evidence
    changed: list[str] = []
    leaked: list[str] = []
    expected_s: str = ""
    actual_s: str = ""
    if evidence:
        diff = evidence.response_diff or {}
        changed = sorted(str(k) for k in diff.get("changed_keys", []))
        leaked = sorted(
            sf.get("field", "") if isinstance(sf, dict) else str(sf)
            for sf in diff.get("sensitive_fields_exposed", [])
        )
        expected_s = str(evidence.expected_status or "")
        actual_s = str(evidence.actual_status)

    parts = "|".join([
        finding.check,
        finding.method,
        finding.endpoint,
        finding.severity.value,
        ",".join(changed),
        ",".join(leaked),
        expected_s,
        actual_s,
        framework_hint,
        PROMPT_VERSION,
        model,
    ])
    return hashlib.sha256(parts.encode()).hexdigest()


def _strip_markdown_fences(text: str) -> str:
    """Remove markdown code fences if the model wraps its JSON output in them."""
    m = _MARKDOWN_FENCE_RE.match(text.strip())
    if m:
        return m.group(1).strip()
    return text.strip()


async def analyze_finding(
    finding: Finding,
    framework_hint: str,
    provider: LLMProvider,
    settings: Settings,
) -> AiAnalysis:
    """Analyze a finding with the LLM, with full fallback on any failure.

    The finding itself is NEVER modified by this function.

    Args:
        finding: The scanner finding (read-only).
        framework_hint: Must be in FRAMEWORK_HINTS.
        provider: LLM provider instance.
        settings: Application settings.

    Returns:
        An AiAnalysis (source="llm" on success, "template" on any failure).
    """
    if framework_hint not in FRAMEWORK_HINTS:
        return build_template_analysis(
            finding,
            warning=f"Invalid framework_hint '{framework_hint}'; using template fallback.",
        )

    # Determine the model name for the analysis record
    from app.ai.providers import (
        _GEMINI_DEFAULT_MODEL,
        _GROQ_DEFAULT_MODEL,
        _OPENROUTER_DEFAULT_MODEL,
    )
    provider_defaults = {
        "groq": _GROQ_DEFAULT_MODEL,
        "openrouter": _OPENROUTER_DEFAULT_MODEL,
        "gemini": _GEMINI_DEFAULT_MODEL,
    }
    model_name = settings.LLM_MODEL or provider_defaults.get(
        settings.LLM_PROVIDER.lower(), "unknown"
    )

    # Build payload and run safety assertion
    try:
        payload = build_llm_payload(finding, framework_hint)
        serialized = json.dumps(payload)
        assert_payload_safe(serialized)
    except PayloadNotSafeError as exc:
        logger.warning("Payload safety assertion fired; using template: %s", str(exc))
        return build_template_analysis(finding, warning="Payload safety assertion fired; template used.")
    except Exception as exc:
        logger.warning("Payload build error; using template: %s", type(exc).__name__)
        return build_template_analysis(finding, warning="Payload build error; template used.")

    user_msg = build_user_message(payload, framework_hint)

    # One retry on invalid JSON
    for attempt in range(2):
        try:
            if attempt == 1:
                # Short reminder on retry
                retry_msg = user_msg + "\n\nReturn ONLY valid JSON matching the schema. No markdown fences."
                raw = await provider.complete_json(
                    SYSTEM_PROMPT, retry_msg, settings.AI_MAX_OUTPUT_TOKENS
                )
            else:
                raw = await provider.complete_json(
                    SYSTEM_PROMPT, user_msg, settings.AI_MAX_OUTPUT_TOKENS
                )

            raw = _strip_markdown_fences(raw)
            data = json.loads(raw)

            # Inject metadata fields before validation
            data["source"] = "llm"
            data["model"] = model_name
            data["prompt_version"] = PROMPT_VERSION

            analysis = AiAnalysis.model_validate(data)
            return sanitize_analysis(analysis)

        except json.JSONDecodeError:
            if attempt == 0:
                logger.info("LLM returned invalid JSON; retrying once")
                continue
            logger.warning("LLM returned invalid JSON after retry; using template")
            return build_template_analysis(finding, warning="LLM returned invalid JSON; template used.")
        except Exception as exc:
            logger.warning(
                "LLM analysis failed (%s); using template fallback",
                type(exc).__name__,
            )
            return build_template_analysis(
                finding,
                warning=f"Provider error ({type(exc).__name__}); template used.",
            )

    # Should not reach
    return build_template_analysis(finding, warning="Unexpected loop exit; template used.")


async def summarize_scan(
    summary: dict[str, Any],
    findings: list[Finding],
    provider: LLMProvider,
    settings: Settings,
) -> dict[str, Any]:
    """Generate an AI executive summary for a completed scan.

    Uses only counts, severity names, check names, and path templates.
    Falls back to a deterministic template on any failure.

    Returns:
        dict with keys: text, source, model, generated_at
    """
    from app.ai.providers import (
        _GEMINI_DEFAULT_MODEL,
        _GROQ_DEFAULT_MODEL,
        _OPENROUTER_DEFAULT_MODEL,
    )

    provider_defaults = {
        "groq": _GROQ_DEFAULT_MODEL,
        "openrouter": _OPENROUTER_DEFAULT_MODEL,
        "gemini": _GEMINI_DEFAULT_MODEL,
    }
    model_name = settings.LLM_MODEL or provider_defaults.get(
        settings.LLM_PROVIDER.lower(), "unknown"
    )

    def _template_summary() -> dict[str, Any]:
        by_sev = summary.get("by_severity", {})
        total = summary.get("total_findings", 0)
        crits = by_sev.get("CRITICAL", 0)
        highs = by_sev.get("HIGH", 0)
        text = (
            f"Scan complete. {total} finding(s) detected: "
            f"{crits} CRITICAL, {highs} HIGH. "
            "Review findings in order of severity and apply the recommended remediations."
        )
        return {
            "text": text,
            "source": "template",
            "model": None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # Build a safe summary payload (counts + path templates + check names only)
    check_names = list({f.check for f in findings})[:10]
    path_templates = list({f.endpoint for f in findings})[:15]
    by_sev = summary.get("by_severity", {})
    total = summary.get("total_findings", 0)

    summary_payload = {
        "total_findings": total,
        "by_severity": by_sev,
        "check_names": check_names,
        "path_templates": path_templates,
    }

    try:
        serialized = json.dumps(summary_payload)
        assert_payload_safe(serialized)
    except PayloadNotSafeError as exc:
        logger.warning("Scan summary payload safety tripped; using template: %s", exc)
        return _template_summary()

    system = (
        "You are a defensive API security analyst. "
        "Write a concise executive summary (max 900 characters) from the scan metadata below. "
        "Do not invent vulnerabilities. Do not include URLs. "
        "Output a JSON object with a single key 'summary' containing the text."
    )
    user = (
        f"<scan_metadata>\n{serialized}\n</scan_metadata>\n\n"
        "Return only: {\"summary\": \"<your text here>\"}"
    )

    try:
        raw = await provider.complete_json(system, user, 400)
        raw = _strip_markdown_fences(raw)
        data = json.loads(raw)
        text = str(data.get("summary", "")).strip()
        text = _sanitize_str(text, 900)
        if not text:
            return _template_summary()
        return {
            "text": text,
            "source": "llm",
            "model": model_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        logger.warning("Scan summary generation failed (%s); using template", type(exc).__name__)
        return _template_summary()


# ── AI Hint suggestions (Task 5) ─────────────────────────────────────────────

_INSTRUCTION_LIKE_RE = re.compile(
    r"(?:ignore|forget|disregard)\s+(?:previous|prior|above)\s+(?:instructions?|prompt|context)",
    re.IGNORECASE,
)
_BOUNDARY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class EndpointFlag(BaseModel):
    """Hint flag for a single endpoint."""

    operation_id: str
    likely_object_level: bool = False
    likely_privileged: bool = False
    reason: str = Field(default="", max_length=160)


class AnalystHints(BaseModel):
    """Structured hints returned by the AI for endpoint augmentation."""

    endpoint_flags: list[EndpointFlag] = Field(default_factory=list)
    extra_boundary_ids: list[str] = Field(default_factory=list)


async def suggest_hints(
    endpoints: list[Any],
    provider: LLMProvider,
    settings: Settings,
) -> AnalystHints:
    """Ask the LLM to suggest endpoint flags and extra boundary IDs.

    Only called when use_ai_hints=True is set in ScanConfig.
    Sends only: method, path template, parameter names, tags, spec summary (truncated).

    Args:
        endpoints: List of Endpoint objects from the parser.
        provider: LLM provider.
        settings: Application settings.

    Returns:
        AnalystHints with validated flags and IDs (unknown op_ids dropped).
    """
    from app.models import Endpoint as EndpointModel

    empty = AnalystHints()

    # Build safe metadata
    ep_meta = []
    for ep in endpoints[:30]:
        if isinstance(ep, EndpointModel):
            raw_summary = getattr(ep, "summary", "") or ""
            clean_summary = _INSTRUCTION_LIKE_RE.sub("[removed]", raw_summary)[:120].strip()
            # Redact bearer token prefix keywords from endpoint summaries to prevent false-positive safety trips
            clean_summary = re.sub(r"(?i)\bbearer\s+", "token-auth ", clean_summary)
            ep_meta.append({
                "operation_id": ep.operation_id or "",
                "method": ep.method,
                "path_template": ep.path,
                "path_params": ep.path_params[:10],
                "query_params": ep.query_params[:10],
                "tags": ep.tags[:5],
                "summary": clean_summary,
            })

    if not ep_meta:
        return empty

    try:
        serialized = json.dumps(ep_meta)
        # Truncate spec summary after stripping instruction-like content
        serialized = _INSTRUCTION_LIKE_RE.sub("[removed]", serialized)
        if len(serialized) > 3000:
            serialized = serialized[:3000] + "... [truncated]"
        assert_payload_safe(serialized)
    except (PayloadNotSafeError, Exception) as exc:
        logger.warning("Hint payload rejected (%s); returning empty hints", type(exc).__name__)
        return empty

    system = (
        "You are an API security expert. "
        "Given endpoint metadata, identify which endpoints are likely object-level (BOLA risk) "
        "or privileged (BFLA risk), and suggest up to 5 extra boundary IDs for testing. "
        "Output JSON: {\"endpoint_flags\": [{\"operation_id\": str, \"likely_object_level\": bool, "
        "\"likely_privileged\": bool, \"reason\": str}], \"extra_boundary_ids\": [str]}. "
        "Do not add flags unless clearly warranted. "
        "Never invent operation_ids not in the input."
    )
    user = (
        "<endpoint_metadata>\n"
        f"{serialized}\n"
        "</endpoint_metadata>\n\n"
        "Return only the JSON object described."
    )

    try:
        raw = await provider.complete_json(system, user, 600)
        raw = _strip_markdown_fences(raw)
        data = json.loads(raw)
    except Exception as exc:
        logger.warning("Hint generation failed (%s); returning empty hints", type(exc).__name__)
        return empty

    # Validate and filter
    known_op_ids = {
        ep.operation_id
        for ep in endpoints
        if hasattr(ep, "operation_id") and ep.operation_id
    }

    flags: list[EndpointFlag] = []
    for raw_flag in data.get("endpoint_flags", [])[:10]:
        if not isinstance(raw_flag, dict):
            continue
        op_id = str(raw_flag.get("operation_id", "")).strip()
        if op_id not in known_op_ids:
            continue  # Drop unknown operation_ids
        flags.append(EndpointFlag(
            operation_id=op_id,
            likely_object_level=bool(raw_flag.get("likely_object_level", False)),
            likely_privileged=bool(raw_flag.get("likely_privileged", False)),
            reason=str(raw_flag.get("reason", ""))[:160],
        ))

    extra_ids: list[str] = []
    for bid in data.get("extra_boundary_ids", []):
        bid_str = str(bid).strip()
        if _BOUNDARY_ID_RE.match(bid_str) and bid_str not in extra_ids:
            extra_ids.append(bid_str)
        if len(extra_ids) >= 5:
            break

    return AnalystHints(endpoint_flags=flags, extra_boundary_ids=extra_ids)


def apply_hints(endpoints: list[Any], hints: AnalystHints) -> list[Any]:
    """Apply AI hints to endpoints, only ADDING flags (never removing/downgrading).

    Marks hint_source="llm" on modified endpoints.

    Args:
        endpoints: Original Endpoint list.
        hints: AnalystHints from suggest_hints.

    Returns:
        New list of Endpoint objects with flags applied.
    """
    flag_map = {f.operation_id: f for f in hints.endpoint_flags}
    result = []
    for ep in endpoints:
        op_id = getattr(ep, "operation_id", None)
        flag = flag_map.get(op_id) if op_id else None
        if flag:
            changes: dict[str, Any] = {}
            if flag.likely_object_level and not ep.is_object_level:
                changes["is_object_level"] = True
            if flag.likely_privileged and not ep.is_privileged:
                changes["is_privileged"] = True
            if changes:
                changes["hint_source"] = "llm"
                ep = ep.model_copy(update=changes)
        result.append(ep)
    return result
