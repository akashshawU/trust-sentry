"""TrustInterceptor — wraps AI service calls with PII scanning and structured logging."""

from datetime import datetime, timezone
from typing import Any

import structlog
from presidio_analyzer import RecognizerResult
from pydantic import BaseModel

# Re-use the custom-registry analyzer from the privacy pillar so that the
# interceptor entity log also detects India / Middle East PII (Aadhaar, PAN,
# Emirates ID, etc.) — not just standard global Presidio entities.
from trust_agent.pillars.privacy import _analyzer

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class ServiceCall(BaseModel):
    prompt: str
    caller_id: str
    service_name: str
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 1024
    metadata: dict[str, Any] = {}


class PiiScanResult(BaseModel):
    entity_types: list[str]
    entity_count: int
    risk_score: float  # 0-100; higher = more PII detected


class LogEntry(BaseModel):
    timestamp: str
    caller_id: str
    service_name: str
    model: str
    input_pii: PiiScanResult
    output_pii: PiiScanResult
    input_tokens: int
    output_tokens: int
    metadata: dict[str, Any]


class InterceptorResult(BaseModel):
    response_text: str
    log_entry: LogEntry


# ---------------------------------------------------------------------------
# PII check
# ---------------------------------------------------------------------------

def check_pii(text: str, language: str = "en") -> PiiScanResult:
    """
    Run Presidio analysis on *text* and return a structured PII scan result.

    Args:
        text: The text to scan for personally identifiable information.
        language: BCP-47 language code for the analyzer (default: ``"en"``).

    Returns:
        A :class:`PiiScanResult` with detected entity types, count, and a
        0-100 risk score that scales with entity count and detection confidence.
    """
    results: list[RecognizerResult] = _analyzer.analyze(text=text, language=language)

    entity_types: list[str] = list({r.entity_type for r in results})

    if results:
        avg_confidence = sum(r.score for r in results) / len(results)
        risk_score = round(min(100.0, len(results) * 10 * avg_confidence), 2)
    else:
        risk_score = 0.0

    return PiiScanResult(
        entity_types=entity_types,
        entity_count=len(results),
        risk_score=risk_score,
    )


# ---------------------------------------------------------------------------
# Interceptor
# ---------------------------------------------------------------------------

class TrustInterceptor:
    """
    Wraps an Anthropic API call with trust controls.

    For every :class:`ServiceCall` the interceptor:

    1. Logs the request with a UTC timestamp, ``caller_id``, and
       ``service_name``.
    2. Scans the input prompt for PII via :func:`check_pii`.
    3. Calls the Anthropic Messages API to obtain the model response.
    4. Scans the response text for PII via :func:`check_pii`.
    5. Returns the response text and a structured :class:`LogEntry`.
    """

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def intercept(self, call: ServiceCall) -> InterceptorResult:
        """
        Execute a trust-governed AI service call.

        Args:
            call: A :class:`ServiceCall` containing the prompt, caller
                  identity, target service, and optional model parameters.

        Returns:
            An :class:`InterceptorResult` with the model's response text
            and a :class:`LogEntry` capturing all trust-relevant signals.

        Raises:
            anthropic.APIError: Propagated if the Anthropic API returns a
                non-retryable error.
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        log.info(
            "service_call_received",
            timestamp=timestamp,
            caller_id=call.caller_id,
            service_name=call.service_name,
            model=call.model,
        )

        # Step 1 — PII scan on input
        input_pii = check_pii(call.prompt)
        self._log_pii_result("input", call.caller_id, input_pii)

        # Step 2 — call Anthropic
        response_text, input_tokens, output_tokens = self._call_anthropic(call)

        # Step 3 — PII scan on output
        output_pii = check_pii(response_text)
        self._log_pii_result("output", call.caller_id, output_pii)

        log_entry = LogEntry(
            timestamp=timestamp,
            caller_id=call.caller_id,
            service_name=call.service_name,
            model=call.model,
            input_pii=input_pii,
            output_pii=output_pii,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            metadata=call.metadata,
        )

        log.info(
            "service_call_completed",
            caller_id=call.caller_id,
            service_name=call.service_name,
            input_pii_risk=input_pii.risk_score,
            output_pii_risk=output_pii.risk_score,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )

        return InterceptorResult(response_text=response_text, log_entry=log_entry)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _call_anthropic(self, call: ServiceCall) -> tuple[str, int, int]:
        """Return a mock response; replace with a real API call once a key is configured."""
        mock_text = "[AI Response - connect API key to enable]"
        # Approximate token counts so downstream scoring has realistic values
        input_tokens = len(call.prompt.split())
        output_tokens = len(mock_text.split())
        return mock_text, input_tokens, output_tokens

    @staticmethod
    def _log_pii_result(direction: str, caller_id: str, result: PiiScanResult) -> None:
        if result.entity_count > 0:
            log.warning(
                "pii_detected",
                direction=direction,
                caller_id=caller_id,
                entity_types=result.entity_types,
                entity_count=result.entity_count,
                risk_score=result.risk_score,
            )
        else:
            log.info(
                "pii_clear",
                direction=direction,
                caller_id=caller_id,
            )
