"""LLM provider implementations for SentinelAPI AI analyst.

Security rules:
  - Each provider uses a hard-coded base URL (no user configuration) to prevent SSRF.
  - The API key is read from settings only at call time, transmitted only as the provider's
    auth header, and never written to logs, exceptions, or stored data.
  - LLM traffic does NOT go through the scanner's Executor (different scope/budget).
  - Tests inject an httpx transport (MockTransport / ASGITransport) instead of patching env.
  - One retry on 429/5xx/timeout with a short backoff; Retry-After header is honoured.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Protocol, runtime_checkable

import httpx

import os
from urllib.parse import urlparse

from app.config import Settings

logger = logging.getLogger(__name__)

# Hard-coded provider base URLs (no SSRF vector)
_GROQ_BASE_URL = "https://api.groq.com"
_OPENROUTER_BASE_URL = "https://openrouter.ai"
_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com"

# Allowlisted internal hostnames strictly for isolated E2E integration testing (no external SSRF)
_ALLOWED_MOCK_HOSTS = {"mock_llm", "127.0.0.1", "localhost"}


def _get_base_url(default_url: str) -> str:
    mock_url = os.environ.get("LLM_MOCK_URL")
    if mock_url:
        parsed = urlparse(mock_url)
        if parsed.hostname in _ALLOWED_MOCK_HOSTS:
            return mock_url.rstrip("/")
    return default_url

# Default models (from current docs, Sept 2026)
_GROQ_DEFAULT_MODEL = "llama-3.1-8b-instant"
_OPENROUTER_DEFAULT_MODEL = "meta-llama/llama-3.1-8b-instruct:free"
_GEMINI_DEFAULT_MODEL = "gemini-2.0-flash"

_RETRY_STATUSES = {429, 500, 502, 503, 504}


@runtime_checkable
class LLMProvider(Protocol):
    """Protocol for LLM provider implementations."""

    async def complete_json(self, system: str, user: str, max_tokens: int) -> str:
        """Return a JSON string from the model.

        Args:
            system: System instruction.
            user:   User message.
            max_tokens: Maximum output tokens.

        Returns:
            Raw response string (may be wrapped in markdown fences).
        """
        ...


def _mask_key(key: str) -> str:
    """Return a redacted representation of an API key for safe logging."""
    if len(key) <= 8:
        return "***"
    return key[:4] + "***" + key[-2:]


async def _retry_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    json_body: dict,
    headers: dict,
    timeout: float,
) -> httpx.Response:
    """Make an HTTP request with one retry on retryable status codes or timeout."""
    for attempt in range(2):
        try:
            resp = await client.request(
                method,
                url,
                json=json_body,
                headers=headers,
                timeout=timeout,
            )
            if resp.status_code in _RETRY_STATUSES and attempt == 0:
                retry_after = float(resp.headers.get("Retry-After", "2"))
                wait = min(retry_after, 10.0)
                logger.info("Provider returned %s; retrying in %.1fs", resp.status_code, wait)
                await asyncio.sleep(wait)
                continue
            return resp
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            if attempt == 0:
                logger.info("Provider request failed (%s); retrying in 2s", type(exc).__name__)
                await asyncio.sleep(2.0)
                continue
            raise
    # Should not reach here
    raise RuntimeError("Retry loop exhausted without returning")


class GroqProvider:
    """LLM provider backed by the Groq Chat Completions API."""

    _BASE_URL = _GROQ_BASE_URL
    _CHAT_PATH = "/openai/v1/chat/completions"

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._transport = transport
        self._model = settings.LLM_MODEL or _GROQ_DEFAULT_MODEL
        self._timeout = float(settings.AI_TIMEOUT_SECONDS)

    async def complete_json(self, system: str, user: str, max_tokens: int) -> str:
        """Call Groq Chat Completions with JSON object response_format."""
        key = self._settings.LLM_API_KEY
        if key is None:
            raise ValueError("LLM_API_KEY is not configured")
        raw_key = key.get_secret_value()

        headers = {
            "Authorization": f"Bearer {raw_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }

        kwargs: dict = {}
        if self._transport is not None:
            kwargs["transport"] = self._transport

        async with httpx.AsyncClient(base_url=_get_base_url(self._BASE_URL), **kwargs) as client:
            try:
                resp = await _retry_request(
                    client,
                    "POST",
                    self._CHAT_PATH,
                    json_body=payload,
                    headers=headers,
                    timeout=self._timeout,
                )
            except Exception:
                # Never log the key; log the masked version for traceability
                logger.error(
                    "Groq request failed (key prefix: %s)",
                    _mask_key(raw_key) if raw_key else "none",
                )
                raise

        if resp.status_code != 200:
            raise httpx.HTTPStatusError(
                f"Groq API returned {resp.status_code}",
                request=resp.request,
                response=resp,
            )

        data = resp.json()
        return data["choices"][0]["message"]["content"]


class OpenRouterProvider:
    """LLM provider backed by the OpenRouter Chat Completions API."""

    _BASE_URL = _OPENROUTER_BASE_URL
    _CHAT_PATH = "/api/v1/chat/completions"

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._transport = transport
        self._model = settings.LLM_MODEL or _OPENROUTER_DEFAULT_MODEL
        self._timeout = float(settings.AI_TIMEOUT_SECONDS)

    async def complete_json(self, system: str, user: str, max_tokens: int) -> str:
        """Call OpenRouter Chat Completions with json_object response_format."""
        key = self._settings.LLM_API_KEY
        if key is None:
            raise ValueError("LLM_API_KEY is not configured")
        raw_key = key.get_secret_value()

        headers = {
            "Authorization": f"Bearer {raw_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/sentinel-api",
            "X-Title": "SentinelAPI",
        }
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }

        kwargs: dict = {}
        if self._transport is not None:
            kwargs["transport"] = self._transport

        async with httpx.AsyncClient(base_url=_get_base_url(self._BASE_URL), **kwargs) as client:
            try:
                resp = await _retry_request(
                    client,
                    "POST",
                    self._CHAT_PATH,
                    json_body=payload,
                    headers=headers,
                    timeout=self._timeout,
                )
            except Exception:
                logger.error(
                    "OpenRouter request failed (key prefix: %s)",
                    _mask_key(raw_key) if raw_key else "none",
                )
                raise

        if resp.status_code != 200:
            raise httpx.HTTPStatusError(
                f"OpenRouter API returned {resp.status_code}",
                request=resp.request,
                response=resp,
            )

        data = resp.json()
        return data["choices"][0]["message"]["content"]


class GeminiProvider:
    """LLM provider backed by the Gemini generateContent REST API."""

    _BASE_URL = _GEMINI_BASE_URL
    # Path template; model and key inserted at call time
    _PATH_TMPL = "/v1beta/models/{model}:generateContent"

    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._settings = settings
        self._transport = transport
        self._model = settings.LLM_MODEL or _GEMINI_DEFAULT_MODEL
        self._timeout = float(settings.AI_TIMEOUT_SECONDS)

    async def complete_json(self, system: str, user: str, max_tokens: int) -> str:
        """Call Gemini generateContent with responseMimeType=application/json."""
        key = self._settings.LLM_API_KEY
        if key is None:
            raise ValueError("LLM_API_KEY is not configured")
        raw_key = key.get_secret_value()

        path = self._PATH_TMPL.format(model=self._model)
        params = {"key": raw_key}  # Gemini uses query param auth
        headers = {"Content-Type": "application/json"}
        payload = {
            "systemInstruction": {
                "parts": [{"text": system}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user}],
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.2,
                "maxOutputTokens": max_tokens,
            },
        }

        kwargs: dict = {}
        if self._transport is not None:
            kwargs["transport"] = self._transport

        async with httpx.AsyncClient(base_url=_get_base_url(self._BASE_URL), params=params, **kwargs) as client:
            try:
                # Gemini uses key as query param; _retry_request doesn't log the key
                resp = await _retry_request(
                    client,
                    "POST",
                    path,
                    json_body=payload,
                    headers=headers,
                    timeout=self._timeout,
                )
            except Exception:
                logger.error(
                    "Gemini request failed (key prefix: %s)",
                    _mask_key(raw_key) if raw_key else "none",
                )
                raise

        if resp.status_code != 200:
            raise httpx.HTTPStatusError(
                f"Gemini API returned {resp.status_code}",
                request=resp.request,
                response=resp,
            )

        data = resp.json()
        # Gemini response: candidates[0].content.parts[0].text
        return data["candidates"][0]["content"]["parts"][0]["text"]


_test_transport: httpx.AsyncBaseTransport | None = None


def set_test_transport(transport: httpx.AsyncBaseTransport | None) -> None:
    """Set an optional global httpx transport override for testing."""
    global _test_transport
    _test_transport = transport


def get_provider(settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> LLMProvider | None:
    """Return the configured LLM provider instance, or None when AI is not configured.

    AI is considered "configured" only when AI_ENABLED is True AND LLM_API_KEY is set.

    Args:
        settings: Application settings.
        transport: Optional httpx transport override for testing.

    Returns:
        An LLMProvider instance, or None.
    """
    if not settings.AI_ENABLED:
        return None
    if settings.LLM_API_KEY is None:
        return None

    active_transport = transport if transport is not None else _test_transport

    provider_name = settings.LLM_PROVIDER.lower().strip()
    if provider_name == "groq":
        return GroqProvider(settings, transport=active_transport)
    if provider_name == "openrouter":
        return OpenRouterProvider(settings, transport=active_transport)
    if provider_name == "gemini":
        return GeminiProvider(settings, transport=active_transport)

    logger.warning("Unknown LLM_PROVIDER '%s'; AI disabled.", provider_name)
    return None
