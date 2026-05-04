"""Pillar 8: Operational Resilience — real in-memory service health tracking."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# In-memory metrics store  (module-level singleton)
# ---------------------------------------------------------------------------

SERVICE_METRICS: dict[str, dict] = {}

_MIN_CALLS_FOR_BASELINE = 5   # need this many calls before a stable baseline exists
_BASELINE_LATENCY_DEFAULT = 500.0  # ms — assumed baseline before real data arrives


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ResilienceResult:
    resilience_score: float
    service_name: str
    total_calls: int
    error_rate: float                 # percentage 0–100
    avg_latency_ms: float
    latency_vs_baseline: str          # normal | elevated | critical
    health_status: str                # HEALTHY | DEGRADED | CRITICAL
    recommendation: str = ""


# ---------------------------------------------------------------------------
# Legacy Pydantic model kept for /pillars/resilience endpoint
# ---------------------------------------------------------------------------

class ModelHealthMetrics(BaseModel):
    accuracy: float
    baseline_accuracy: float
    data_quality_score: float
    latency_p99_ms: float
    error_rate: float
    uptime_fraction: float


class ResilienceResultLegacy(BaseModel):
    drift_detected: bool
    drift_magnitude: float
    score: float


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def check_resilience(
    service_name: str,
    latency_ms: float | None = None,
    had_error: bool = False,
) -> ResilienceResult:
    """
    Record one service call for *service_name* and return a current resilience score.

    Metrics are accumulated in :data:`SERVICE_METRICS` across calls within the same
    process lifetime.  A baseline latency is established after the first
    ``_MIN_CALLS_FOR_BASELINE`` calls.

    Args:
        service_name: Unique identifier for the AI service being monitored.
        latency_ms:   Round-trip latency for this call in milliseconds (optional).
        had_error:    Whether this call returned an error.

    Returns:
        A :class:`ResilienceResult` with a 0-100 resilience score (higher = healthier).
    """
    # ── Initialise metrics record ─────────────────────────────────────────
    if service_name not in SERVICE_METRICS:
        SERVICE_METRICS[service_name] = {
            "call_count":          0,
            "error_count":         0,
            "total_latency_ms":    0.0,
            "last_called":         None,
            "baseline_latency_ms": _BASELINE_LATENCY_DEFAULT,
            "score_history":       [],   # last 20 composite scores
        }

    m = SERVICE_METRICS[service_name]
    m["call_count"]   += 1
    m["last_called"]   = datetime.now(timezone.utc)
    if had_error:
        m["error_count"] += 1
    if latency_ms is not None:
        m["total_latency_ms"] += latency_ms
        # Set baseline after MIN_CALLS calls
        if m["call_count"] == _MIN_CALLS_FOR_BASELINE and m["total_latency_ms"] > 0:
            m["baseline_latency_ms"] = m["total_latency_ms"] / m["call_count"]

    # ── Derived metrics ───────────────────────────────────────────────────
    call_count = m["call_count"]
    error_rate = (m["error_count"] / call_count * 100) if call_count > 0 else 0.0
    avg_latency = (m["total_latency_ms"] / call_count) if call_count > 0 and m["total_latency_ms"] > 0 else 0.0
    baseline    = m["baseline_latency_ms"]

    # ── Scoring ───────────────────────────────────────────────────────────
    score = 100.0

    if error_rate > 20:
        score -= 30
    elif error_rate > 10:
        score -= 15
    elif error_rate > 5:
        score -= 8

    latency_vs_baseline = "normal"
    if latency_ms is not None and baseline > 0:
        ratio = latency_ms / baseline
        if ratio > 3.0:
            score -= 25
            latency_vs_baseline = "critical"
        elif ratio > 2.0:
            score -= 12
            latency_vs_baseline = "elevated"
        elif ratio > 1.5:
            score -= 6
            latency_vs_baseline = "elevated"

    if call_count < _MIN_CALLS_FOR_BASELINE:
        score -= 5  # not enough data yet

    score = max(0.0, min(100.0, round(score, 2)))

    # ── Health label ──────────────────────────────────────────────────────
    if score >= 80:
        health_status = "HEALTHY"
        recommendation = f"Service '{service_name}' is operating within normal parameters."
    elif score >= 50:
        health_status = "DEGRADED"
        recommendation = (
            f"Service '{service_name}' shows degraded performance. "
            "Check error logs and latency trends."
        )
    else:
        health_status = "CRITICAL"
        recommendation = (
            f"Service '{service_name}' is in a critical state. "
            "Immediate investigation required — escalate to on-call team."
        )

    return ResilienceResult(
        resilience_score=score,
        service_name=service_name,
        total_calls=call_count,
        error_rate=round(error_rate, 2),
        avg_latency_ms=round(avg_latency, 1),
        latency_vs_baseline=latency_vs_baseline,
        health_status=health_status,
        recommendation=recommendation,
    )


def evaluate_resilience(metrics: ModelHealthMetrics) -> ResilienceResultLegacy:
    """Legacy endpoint handler — evaluates pre-supplied telemetry metrics."""
    score = 100.0
    drift_magnitude = round(metrics.baseline_accuracy - metrics.accuracy, 4)
    drift_detected  = drift_magnitude > 0.05

    if drift_detected:
        score -= min(30.0, drift_magnitude * 300)
    score -= max(0.0, (100.0 - metrics.data_quality_score) * 0.3)
    if metrics.latency_p99_ms > 2000.0:
        score -= min(20.0, (metrics.latency_p99_ms - 2000.0) / 100)
    if metrics.error_rate > 0.05:
        score -= min(25.0, (metrics.error_rate - 0.05) * 500)
    score -= max(0.0, (1.0 - metrics.uptime_fraction) * 100)
    score  = max(0.0, round(score, 2))

    return ResilienceResultLegacy(
        drift_detected=drift_detected,
        drift_magnitude=drift_magnitude,
        score=score,
    )
