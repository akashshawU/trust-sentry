"""FastAPI backend — trust-aware AI proxy with pillar evaluation endpoints."""

import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any

import structlog
import uvicorn
from dotenv import load_dotenv
from fastapi import Body, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from trust_agent.interceptor import ServiceCall, TrustInterceptor
from trust_agent.pillars.access_control import AccessRequest, evaluate_access
from trust_agent.pillars.fairness import GroupOutcomes, check_fairness, compute_fairness
from trust_agent.pillars.operational_resilience import ModelHealthMetrics, evaluate_resilience
from trust_agent.pillars.privacy import analyze_and_anonymize
from trust_agent.pillars.regulatory_compliance import (
    ComplianceControl, check_compliance, evaluate_compliance,
)
from trust_agent.pillars.explainability import check_explainability
from trust_agent.pillars.security import check_security, scan_input
from trust_agent.scoring.engine import TrustReport, TrustScoreEngine, generate_trust_report

load_dotenv(override=True)
log = structlog.get_logger()

# ---------------------------------------------------------------------------
# In-memory log store — keeps the last 100 entries (thread-safe append/pop)
# ---------------------------------------------------------------------------

_LOG_STORE: deque[dict[str, Any]] = deque(maxlen=100)


def _status_from_score(score: float) -> str:
    """Derive a GREEN / AMBER / RED status from a 0-100 score."""
    if score >= 80:
        return "GREEN"
    if score >= 50:
        return "AMBER"
    return "RED"


def _pillar_log(
    service_name: str,
    pillar_tested: str,
    score: float,
    extra: dict[str, Any] | None = None,
    input_pii: dict[str, Any] | None = None,
) -> None:
    """Append a pillar-test call to _LOG_STORE so it appears in the Recent Calls feed."""
    entry: dict[str, Any] = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "caller_id":     "pillar-test",
        "service_name":  service_name,
        "pillar_tested": pillar_tested,
        "_composite_score": round(score, 2),
        "_status":       _status_from_score(score),
        "input_pii":     input_pii or {"entity_count": 0, "entity_types": []},
        "output_pii":    {"entity_count": 0, "entity_types": []},
        "metadata":      extra or {},
    }
    _LOG_STORE.append(entry)


# ---------------------------------------------------------------------------
# Singletons — created once at startup so Presidio models load only once
# ---------------------------------------------------------------------------

_interceptor = TrustInterceptor()
_score_engine = TrustScoreEngine()

# ---------------------------------------------------------------------------
# OpenAPI tag definitions (appear as section headers in /docs)
# ---------------------------------------------------------------------------

_TAGS: list[dict[str, Any]] = [
    {
        "name": "system",
        "description": "Health monitoring and status.",
    },
    {
        "name": "core",
        "description": (
            "**Main analysis engine** — intercept, score, and audit any AI call. "
            "Every request is scanned for PII, scored across four trust dimensions, "
            "and persisted to the in-memory audit log."
        ),
    },
    {
        "name": "pillars",
        "description": (
            "**Individual governance pillar checks** — run any pillar standalone "
            "without going through the full intercept pipeline. Useful for targeted "
            "audits, CI gates, and debugging specific trust dimensions."
        ),
    },
    {
        "name": "trust",
        "description": (
            "**Full trust report across all 8 pillars** — aggregates pre-computed "
            "pillar scores into a composite grade and returns prioritised remediation "
            "recommendations aligned to ISO 42001, NIST AI RMF, and the EU AI Act."
        ),
    },
]

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="AI Trust Agent — Uniqus Consultech",
    description="""
## Uniqus Consultech — Enterprise AI Governance Platform

Trust-aware AI proxy: intercept, score, and audit every AI service call across 8 governance pillars.

**Live Dashboard:** http://localhost:8000

**Frameworks:** ISO 42001 · NIST AI RMF · EU AI Act · KPMG Trusted AI · McKinsey RAI 2026
""",
    version="1.0.0",
    contact={
        "name": "Trust Agent Team",
        "url": "https://github.com/your-org/ai-trust-agent",
        "email": "trust-agent@your-org.com",
    },
    license_info={
        "name": "MIT",
    },
    openapi_tags=_TAGS,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the dashboard and any future static assets
_STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    prompt: str
    caller_id: str
    service_name: str
    model: str = "claude-sonnet-4-6"
    max_tokens: int = 1024
    metadata: dict[str, Any] = {}


class TrustScoreResponse(BaseModel):
    reliability_score:    float
    privacy_score:        float
    security_score:       float
    access_score:         float
    fairness_score:       float
    explainability_score: float
    compliance_score:     float
    resilience_score:     float
    composite_score:      float
    status:               str
    pillar_details:       dict[str, Any] = {}


class AnalyzeResponse(BaseModel):
    response_text: str
    trust_score: TrustScoreResponse
    log_entry: dict[str, Any]


# ---------------------------------------------------------------------------
# Reusable Body() definitions with openapi_examples
# ---------------------------------------------------------------------------

_AnalyzeBody = Body(
    openapi_examples={
        "healthcare_risk": {
            "summary": "Healthcare risk analysis",
            "description": "Ask the AI to summarise LLM risks in a regulated domain.",
            "value": {
                "prompt": "Summarise the top five risks of deploying LLMs in clinical decision support systems.",
                "caller_id": "analyst-001",
                "service_name": "risk-summarizer",
            },
        },
        "pii_in_prompt": {
            "summary": "Prompt containing PII (triggers privacy penalty)",
            "description": "Demonstrates how PII in the input lowers the privacy score.",
            "value": {
                "prompt": "Draft a follow-up email for John Smith at john.smith@acme.com regarding his account number 4111-1111-1111-1111.",
                "caller_id": "sales-bot",
                "service_name": "email-drafter",
            },
        },
        "simple_qa": {
            "summary": "Simple Q&A (clean, no PII)",
            "description": "A clean prompt that should score GREEN across all dimensions.",
            "value": {
                "prompt": "What is the difference between AI safety and AI security?",
                "caller_id": "user-demo",
                "service_name": "qa-bot",
            },
        },
    }
)

_PrivacyBody = Body(
    openapi_examples={
        "mixed_pii": {
            "summary": "Text with multiple PII types",
            "description": "Detects person name, email, phone, and credit card number.",
            "value": {
                "text": "Please process the refund for Jane Doe (jane.doe@example.com, +1-800-555-0199). Her card ending 4242 was charged $349.",
                "language": "en",
            },
        },
        "clean_text": {
            "summary": "Clean text (no PII expected)",
            "description": "Should return zero entities and a risk score of 0.",
            "value": {
                "text": "The quarterly earnings report shows a 12% increase in gross margin.",
                "language": "en",
            },
        },
    }
)

_TrustReportBody = Body(
    openapi_examples={
        "high_risk_model": {
            "summary": "High-risk model (triggers AMBER/RED)",
            "description": "A model with weak fairness and explainability scores.",
            "value": {
                "model_id": "credit-scoring-v2",
                "pillar_scores": {
                    "privacy": 85.0,
                    "access_control": 90.0,
                    "fairness": 48.0,
                    "explainability": 35.0,
                    "security": 88.0,
                    "regulatory_compliance": 70.0,
                    "operational_resilience": 92.0,
                },
            },
        },
        "well_governed_model": {
            "summary": "Well-governed model (GREEN across pillars)",
            "description": "A mature model with strong scores on all eight pillars.",
            "value": {
                "model_id": "fraud-detection-v5",
                "pillar_scores": {
                    "privacy": 95.0,
                    "access_control": 98.0,
                    "fairness": 87.0,
                    "explainability": 82.0,
                    "security": 96.0,
                    "regulatory_compliance": 91.0,
                    "operational_resilience": 94.0,
                },
            },
        },
        "custom_weights": {
            "summary": "Custom pillar weights (fairness-heavy)",
            "description": "Override the default equal weighting to emphasise fairness and explainability for a lending model.",
            "value": {
                "model_id": "lending-model-v3",
                "pillar_scores": {
                    "privacy": 80.0,
                    "access_control": 85.0,
                    "fairness": 72.0,
                    "explainability": 68.0,
                    "security": 90.0,
                    "regulatory_compliance": 78.0,
                    "operational_resilience": 88.0,
                },
                "weights": {
                    "fairness": 3.0,
                    "explainability": 2.5,
                    "regulatory_compliance": 2.0,
                    "privacy": 1.5,
                    "security": 1.5,
                    "access_control": 1.0,
                    "operational_resilience": 1.0,
                },
            },
        },
    }
)


# ---------------------------------------------------------------------------
# System endpoints
# ---------------------------------------------------------------------------

@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/static/dashboard.html")


@app.get(
    "/health",
    tags=["system"],
    summary="Health check",
    response_description="Service liveness status",
)
def health_check() -> dict[str, str]:
    """Returns `{"status": "ok"}` when the service is up and accepting requests."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Core endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["core"],
    summary="Analyze an AI call end-to-end",
    response_description="AI response text, composite trust score, and full audit log entry",
)
def analyze(request: Annotated[AnalyzeRequest, _AnalyzeBody]) -> AnalyzeResponse:
    """
    Run a prompt through the full trust pipeline:

    1. **PII scan** — Presidio scans the input for personal data before it reaches the model.
    2. **AI call** — The prompt is forwarded to the configured AI service.
    3. **Output PII scan** — The response is scanned for any leaked PII.
    4. **Trust scoring** — Reliability, privacy, access, and hallucination risk are scored 0–100.
    5. **Audit log** — The full entry is persisted and queryable via `GET /logs`.

    The composite score determines the status: **GREEN** ≥ 80 · **AMBER** ≥ 50 · **RED** < 50.
    """
    call = ServiceCall(
        prompt=request.prompt,
        caller_id=request.caller_id,
        service_name=request.service_name,
        model=request.model,
        max_tokens=request.max_tokens,
        metadata=request.metadata,
    )

    try:
        result = _interceptor.intercept(call)
    except Exception as exc:
        log.error("intercept_failed", error=str(exc), caller_id=request.caller_id)
        raise HTTPException(status_code=502, detail=f"AI service call failed: {exc}") from exc

    log_dict = result.log_entry.model_dump()

    # Stamp prompt + response so the engine can run all real pillar checks
    log_dict["_prompt"]   = request.prompt
    log_dict["_response"] = result.response_text

    trust = _score_engine.score(log_dict)

    # Stamp trust scores onto the log dict so /logs carries everything the dashboard needs
    log_dict["_composite_score"] = trust.composite_score
    log_dict["_status"]          = trust.status.value

    # Persist to in-memory log store
    _LOG_STORE.append(log_dict)

    log.info(
        "analyze_complete",
        caller_id=request.caller_id,
        service_name=request.service_name,
        composite_score=trust.composite_score,
        status=trust.status.value,
    )

    return AnalyzeResponse(
        response_text=result.response_text,
        trust_score=TrustScoreResponse(
            reliability_score=trust.reliability_score,
            privacy_score=trust.privacy_score,
            security_score=trust.security_score,
            access_score=trust.access_score,
            fairness_score=trust.fairness_score,
            explainability_score=trust.explainability_score,
            compliance_score=trust.compliance_score,
            resilience_score=trust.resilience_score,
            composite_score=trust.composite_score,
            status=trust.status.value,
            pillar_details=trust.pillar_details,
        ),
        log_entry=log_dict,
    )


@app.get(
    "/logs",
    tags=["core"],
    summary="Retrieve audit log",
    response_description="List of the last 100 intercepted call entries with trust scores",
)
def get_logs() -> dict[str, Any]:
    """
    Returns the last 100 intercepted call log entries, most recent last.

    Each entry includes the timestamp, caller identity, service name, PII scan results
    for both input and output, token counts, and the stamped `_composite_score` and
    `_status` fields used by the live dashboard.
    """
    return {"count": len(_LOG_STORE), "entries": list(_LOG_STORE)}


# ---------------------------------------------------------------------------
# Pillar endpoints
# ---------------------------------------------------------------------------

class PrivacyRequest(BaseModel):
    text: str
    language: str = "en"


@app.post(
    "/pillars/privacy",
    tags=["pillars"],
    summary="Scan text for PII",
    response_description="Detected entities, anonymised text, and a 0–100 risk score",
)
def privacy_scan(request: Annotated[PrivacyRequest, _PrivacyBody]):
    """
    Run Microsoft Presidio's NLP-based PII detection on any text string.

    Identifies entity types such as `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`,
    `CREDIT_CARD`, `US_SSN`, `LOCATION`, and more. Returns the anonymised version of
    the text alongside a risk score where **100 = maximum PII exposure**.
    """
    result = analyze_and_anonymize(request.text, language=request.language)
    log.info("privacy_scan", entities_found=len(result.entities_found),
             critical_entities=result.critical_entities)
    privacy_score = result.privacy_score
    entity_types = [e["entity_type"] for e in result.entities_found]
    _pillar_log(
        service_name="privacy-scan",
        pillar_tested="privacy",
        score=privacy_score,
        input_pii={"entity_count": len(result.entities_found), "entity_types": entity_types},
        extra={"critical_entities": result.critical_entities},
    )
    return result


@app.post(
    "/pillars/access-control",
    tags=["pillars"],
    summary="Evaluate an RBAC access request",
    response_description="Allow/deny decision with the governing policy reason",
)
def access_control_check(request: AccessRequest):
    """
    Check whether a given `role` is permitted to perform `action` on `resource`.

    Uses a built-in RBAC policy table covering `admin`, `analyst`, `developer`,
    and `auditor` roles. Returns the decision, a plain-English reason, and a
    0–100 access score (100 = permitted, 0 = denied).
    """
    decision = evaluate_access(request)
    log.info("access_control_check", allowed=decision.allowed)
    _pillar_log(
        service_name="access-control",
        pillar_tested="access_control",
        score=decision.score,
        extra={"allowed": decision.allowed, "role": request.role, "resource": request.resource},
    )
    return decision


class FairnessRequest(BaseModel):
    groups:      list[GroupOutcomes] = []
    prompt_text: str = ""


@app.post(
    "/pillars/fairness",
    tags=["pillars"],
    summary="Measure disparate impact or scan text for bias",
    response_description="Fairness score with bias detection and disparate impact analysis",
)
def fairness_check(request: FairnessRequest):
    """
    Two modes:
    - **prompt_text** provided: Claude AI (or rule-based fallback) scans the text for
      bias across 10 demographic dimensions. Returns a FairnessResult.
    - **groups** provided: Computes disparate impact ratio (min rate / max rate) across
      demographic groups. Returns a FairnessResultLegacy.

    A disparate impact ratio below 0.8 breaches the US EEOC four-fifths rule.
    """
    if request.prompt_text.strip():
        result = check_fairness(request.prompt_text)
        log.info("fairness_check_text", score=result.fairness_score, mock_mode=result.mock_mode)
        _pillar_log(
            service_name="fairness-check",
            pillar_tested="fairness",
            score=result.fairness_score,
            extra={"bias_count": result.bias_count, "mock_mode": result.mock_mode},
        )
        return result
    result = compute_fairness(request.groups)
    log.info("fairness_check", di_ratio=result.disparate_impact_ratio)
    _pillar_log(
        service_name="fairness-check",
        pillar_tested="fairness",
        score=result.score,
        extra={"disparate_impact_ratio": result.disparate_impact_ratio},
    )
    return result


class SecurityRequest(BaseModel):
    text: str


@app.post(
    "/pillars/security",
    tags=["pillars"],
    summary="Scan for adversarial inputs and prompt injection",
    response_description="Detected threat types, risk level, and 0–100 security score",
)
def security_scan(request: SecurityRequest):
    """
    Scan a text string for security threats using Claude AI (when API key is set)
    or rule-based heuristics as fallback.

    Detects: **prompt injection**, **jailbreak attempts**, **restriction bypass**,
    **social engineering**, **data exfiltration**, **deepfake**, **financial fraud**,
    **misinformation**, **child safety** (forced zero), and **copyright** violations.
    Risk levels: `low` · `medium` · `high` · `critical`.
    """
    result = check_security(request.text)
    risk_map = {
        "BLOCKED":    "critical", "CRITICAL": "critical",
        "HIGH":       "high",     "MEDIUM":   "medium",
        "SUSPICIOUS": "low",      "MINIMAL":  "low", "CLEAN": "low",
    }
    log.info(
        "security_scan",
        severity=result.severity,
        score=result.security_score,
        mock_mode=result.mock_mode,
    )
    _pillar_log(
        service_name="security-scan",
        pillar_tested="security",
        score=result.security_score,
        extra={"severity": result.severity, "threat_count": result.threat_count,
               "mock_mode": result.mock_mode},
    )
    return {
        "security_score":       result.security_score,
        "severity":             result.severity,
        "threats_found":        result.threats_found,
        "threat_count":         result.threat_count,
        "risk_score":           result.risk_score,
        "categories_triggered": result.categories_triggered,
        "mock_mode":            result.mock_mode,
        "reasoning":            result.reasoning,
        "risk_level":           risk_map.get(result.severity, "low"),
    }


class ExplainabilityRequest(BaseModel):
    prompt_text:   str
    response_text: str = ""


@app.post(
    "/pillars/explainability",
    tags=["pillars"],
    summary="Evaluate AI response quality, reasoning, and transparency",
    response_description="Explainability score with reasoning quality and hallucination risk",
)
def explainability_check(request: ExplainabilityRequest):
    """
    Evaluate the quality and transparency of an AI interaction using Gemini AI
    (or rule-based heuristics as fallback).

    Assesses: **reasoning quality**, **transparency**, **hallucination risk**,
    **confidence calibration**, and **structure**. Returns a 0–100 explainability
    score and actionable recommendations.
    """
    result = check_explainability(request.prompt_text, request.response_text)
    log.info(
        "explainability_check",
        score=result.explainability_score,
        mock_mode=result.mock_mode,
    )
    _pillar_log(
        service_name="explainability-check",
        pillar_tested="explainability",
        score=result.explainability_score,
        extra={
            "reasoning_depth": result.reasoning_depth,
            "confidence_indicator": result.confidence_indicator,
            "mock_mode": result.mock_mode,
        },
    )
    return result


class ComplianceRequest(BaseModel):
    text:          str = ""
    frameworks:    list[str] | None = None
    jurisdictions: list[str] | None = None


@app.post(
    "/pillars/compliance",
    tags=["pillars"],
    summary="Score regulatory compliance against global and Middle East frameworks",
    response_description="Compliance score with per-framework violation and trigger analysis",
)
def compliance_check(request: ComplianceRequest):
    """
    Evaluate *text* against regulatory frameworks for violation patterns and trigger keywords.

    - **frameworks**: Optional list of specific framework keys to check
      (e.g. `["gdpr", "uae_pdpl", "ksa_pdpl"]`).
    - **jurisdictions**: Optional list of jurisdiction shortcuts
      (e.g. `["uae", "ksa", "global"]`). Maps to all relevant frameworks automatically.
    - If neither is provided, all frameworks are checked.

    Supported jurisdictions: `uae`, `ksa`, `qatar`, `bahrain`, `kuwait`, `oman`, `gcc`,
    `eu`, `global`.
    """
    result = check_compliance(
        text=request.text,
        frameworks=request.frameworks,
        jurisdictions=request.jurisdictions,
    )
    log.info("compliance_check", score=result.compliance_score)
    _pillar_log(
        service_name="compliance-check",
        pillar_tested="compliance",
        score=result.compliance_score,
        extra={
            "overall_risk":          result.overall_risk,
            "frameworks_checked":    result.frameworks_checked,
            "jurisdictions_covered": result.jurisdictions_covered,
        },
    )
    return result


@app.post(
    "/pillars/resilience",
    tags=["pillars"],
    summary="Assess operational resilience and model drift",
    response_description="Drift detection result, drift magnitude, and 0–100 resilience score",
)
def resilience_check(metrics: ModelHealthMetrics):
    """
    Evaluate the operational health of a deployed model from live telemetry.

    Penalises: accuracy drift > 5 pp vs baseline, p99 latency > 2 000 ms,
    error rate > 5%, data quality degradation, and uptime below 100%.
    A drift magnitude above the threshold sets `drift_detected: true`.
    """
    result = evaluate_resilience(metrics)
    log.info("resilience_check", drift_detected=result.drift_detected)
    _pillar_log(
        service_name="resilience-check",
        pillar_tested="resilience",
        score=result.score,
        extra={"drift_detected": result.drift_detected, "drift_magnitude": result.drift_magnitude},
    )
    return result


# ---------------------------------------------------------------------------
# Trust report
# ---------------------------------------------------------------------------

class TrustReportRequest(BaseModel):
    model_id: str
    pillar_scores: dict[str, float]
    weights: dict[str, float] | None = None


@app.post(
    "/trust-report",
    response_model=TrustReport,
    tags=["trust"],
    summary="Generate a full 8-pillar trust report",
    response_description="Composite trust score, letter grade, and prioritised recommendations",
)
def trust_report(request: Annotated[TrustReportRequest, _TrustReportBody]):
    """
    Aggregate pre-computed pillar scores into a single **TrustReport**.

    - Accepts optional `weights` to override the default equal-weight scheme —
      useful for emphasising pillars that matter most in your regulatory context
      (e.g. give fairness 3× weight for a lending model).
    - Returns a letter grade (**A** · **B** · **C** · **D** · **F**), composite score,
      and a prioritised list of remediation recommendations for any pillar below threshold.
    - All seven pillar keys are required: `privacy`, `access_control`, `fairness`,
      `explainability`, `security`, `regulatory_compliance`, `operational_resilience`.
    """
    required = {
        "privacy", "access_control", "fairness", "explainability",
        "security", "regulatory_compliance", "operational_resilience",
    }
    missing = required - set(request.pillar_scores.keys())
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Missing pillar scores: {', '.join(sorted(missing))}",
        )
    report = generate_trust_report(
        model_id=request.model_id,
        pillar_scores=request.pillar_scores,
        weights=request.weights,
    )
    log.info("trust_report", model_id=request.model_id, grade=report.trust_score.grade)
    _pillar_log(
        service_name="trust-report",
        pillar_tested="trust_report",
        score=report.trust_score.score,
        extra={"model_id": request.model_id, "grade": report.trust_score.grade},
    )
    return report


# ---------------------------------------------------------------------------
# AI Intelligence status endpoint
# ---------------------------------------------------------------------------

@app.get(
    "/ai-status",
    tags=["intelligence"],
    summary="Check whether Gemini AI evaluation is active",
    response_description="AI-powered flag, mock_mode flag, and active model name",
)
def ai_status():
    """
    Returns whether the platform is running with real Gemini AI evaluation
    (``ai_powered: true``) or in rule-based simulation mode (``mock_mode: true``).

    Set the ``GEMINI_API_KEY`` environment variable to enable AI-powered evaluation.
    Get a free key at https://aistudio.google.com/app/apikey
    """
    from trust_agent.intelligence.evaluator import GeminiEvaluator
    ev = GeminiEvaluator()
    return {
        "ai_powered": not ev.mock_mode,
        "mock_mode":  ev.mock_mode,
        "model":      "gemini-2.5-flash" if not ev.mock_mode else None,
        "provider":   "Google Gemini" if not ev.mock_mode else None,
        "message":    (
            "Gemini AI evaluation active (gemini-2.5-flash)"
            if not ev.mock_mode
            else "Simulation mode — set GEMINI_API_KEY to enable AI-powered evaluation"
        ),
    }


# ---------------------------------------------------------------------------
# Debug — intelligence key / provider / mock-mode diagnostics
# ---------------------------------------------------------------------------

@app.get(
    "/debug/intelligence",
    tags=["intelligence"],
    summary="Debug: multi-provider AI status — Groq (primary) + Gemini (fallback)",
    response_description="Per-provider key presence, model names, rate limits, active provider chain, mock_mode, cache size",
)
def debug_intelligence():
    """
    Diagnostic endpoint for the multi-provider AI evaluation layer.

    - **groq_key_loaded** — whether ``GROQ_API_KEY`` is present (primary provider).
    - **groq_model** — Groq model in use (``llama-3.3-70b-versatile``).
    - **groq_rpm_limit** — Groq free-tier rate limit (30 RPM).
    - **gemini_key_loaded** — whether ``GEMINI_API_KEY`` is present (fallback provider).
    - **gemini_model** — Gemini model in use (``gemini-2.0-flash``).
    - **gemini_rpm_limit** — Gemini free-tier RPM limit (15).
    - **gemini_rpd_limit** — Gemini free-tier RPD limit (1 500).
    - **primary_provider** — active primary: ``groq``, ``gemini``, or ``none``.
    - **fallback_provider** — active fallback: ``gemini`` or ``none``.
    - **mock_mode** — ``true`` when *both* providers are unavailable (rule-based only).
    - **intelligence_active** — convenience inverse of ``mock_mode``.
    - **cache_size** — number of entries currently in the 5-minute evaluation cache.
    """
    from trust_agent.intelligence.evaluator import GeminiEvaluator, _evaluation_cache

    groq_key   = os.getenv("GROQ_API_KEY",   "").strip()
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()

    # Instantiate to get real mock_mode / provider chain after key validation
    ev = GeminiEvaluator()

    log.info(
        "debug_intelligence",
        primary_provider=ev.primary_provider,
        fallback_provider=ev.fallback_provider,
        mock_mode=ev.mock_mode,
        cache_size=len(_evaluation_cache),
    )

    return {
        # Groq (primary)
        "groq_key_loaded":  bool(groq_key),
        "groq_key_masked":  (groq_key[:8] + "***") if groq_key else None,
        "groq_model":       "llama-3.3-70b-versatile",
        "groq_rpm_limit":   30,
        # Gemini (fallback)
        "gemini_key_loaded": bool(gemini_key),
        "gemini_key_masked": (gemini_key[:8] + "***") if gemini_key else None,
        "gemini_model":      getattr(ev, "_gemini_model", "gemini-2.0-flash"),
        "gemini_rpm_limit":  15,
        "gemini_rpd_limit":  1500,
        # Active provider chain
        "primary_provider":  ev.primary_provider,
        "fallback_provider": ev.fallback_provider,
        # Health
        "mock_mode":          ev.mock_mode,
        "intelligence_active": not ev.mock_mode,
        "cache_size":         len(_evaluation_cache),
    }


# ---------------------------------------------------------------------------
# Debug — privacy recogniser verification
# ---------------------------------------------------------------------------

@app.get(
    "/debug/privacy",
    tags=["intelligence"],
    summary="Debug: verify custom PII recognisers (Aadhaar, PAN, Emirates ID, etc.)",
    response_description="Entities detected in a fixed test string containing India & UAE PII",
)
def debug_privacy():
    """
    Runs the privacy pillar against a hard-coded test string containing:
    ``Aadhaar 1234 5678 9012``, ``PAN ABCDE1234F``, ``email akash@uniqus.com``,
    and ``Emirates ID 784-1234-1234567-1``.

    A passing result has **entity_count ≥ 2** with ``IN_AADHAAR``, ``IN_PAN``,
    ``EMAIL_ADDRESS``, and ``UAE_EMIRATES_ID`` present in ``entity_types``.
    """
    test_text = (
        "My name is Akash Shaw, "
        "Aadhaar 1234 5678 9012, "
        "PAN ABCDE1234F, "
        "email akash@uniqus.com, "
        "Emirates ID 784-1234-1234567-1"
    )
    result = analyze_and_anonymize(test_text)
    expected = {"IN_AADHAAR", "IN_PAN", "EMAIL_ADDRESS", "UAE_EMIRATES_ID"}
    detected = set(e["entity_type"] for e in result.entities_found)
    missing  = sorted(expected - detected)
    return {
        "test_text":        test_text,
        "entity_count":     result.entity_count,
        "entity_types":     sorted(detected),
        "critical_entities":result.critical_entities,
        "privacy_score":    result.privacy_score,
        "risk_score":       result.risk_score,
        "anonymized_text":  result.anonymized_text,
        "recommendation":   result.recommendation,
        "expected_entities":sorted(expected),
        "missing_entities": missing,
        "all_expected_detected": len(missing) == 0,
        "entities_found":   result.entities_found,
    }


# ---------------------------------------------------------------------------
# Agent B Proxy — Two-Checkpoint Proxy Endpoints
# ---------------------------------------------------------------------------

from trust_agent.proxy.engine import AgentProxy, _SESSIONS
from trust_agent.proxy.agent_simulator import simulate_agent_response
from trust_agent.proxy.scenarios import SCENARIO_LIBRARY, scenario_to_checkpoint_request

_proxy = AgentProxy()


class ProxyInterceptRequest(BaseModel):
    agent_id:           str
    caller_id:          str
    task_description:   str
    requested_actions:  list[dict] = []
    trigger_type:       str = "manual"
    timestamp:          str = ""
    scenario_hint:      str = ""   # optional — used by simulator to pick correct response


class ProxyOutputRequest(BaseModel):
    session_id:             str
    output:                 str
    actions_actually_taken: list[str] = []


class EscalationRequest(BaseModel):
    session_id:  str
    approver_id: str
    notes:       str = ""


@app.post(
    "/proxy/intercept",
    tags=["proxy"],
    summary="Full proxy intercept — Checkpoint 1 → Agent A → Checkpoint 2",
    response_description="Complete proxy session with both checkpoint results",
)
def proxy_intercept(request: ProxyInterceptRequest):
    """
    The main proxy endpoint. Accepts a request intended for Agent A and:

    1. Generates a ``session_id``
    2. Runs **Checkpoint 1** (intent evaluation — guardrails, access control, injection detection)
    3. If **BLOCK**: returns immediately — Agent A never sees the request
    4. If **ESCALATE**: holds request, returns escalation-pending status
    5. If **ALLOW/ALLOW_WITH_RESTRICTIONS**: simulates Agent A response
    6. Runs **Checkpoint 2** (output evaluation — PII scan, compliance, scope check)
    7. Returns approved (possibly redacted) output plus full audit trail

    Agent A is simulated for this POC. In production, replace ``simulate_agent_response``
    with a call to the real agent.
    """
    import uuid as _uuid
    session_id = str(_uuid.uuid4())
    cp1_req = {
        "session_id":        session_id,
        "agent_id":          request.agent_id,
        "caller_id":         request.caller_id,
        "task_description":  request.task_description,
        "requested_actions": request.requested_actions,
        "trigger_type":      request.trigger_type,
        "timestamp":         request.timestamp or __import__("datetime").datetime.now(
                                 __import__("datetime").timezone.utc).isoformat(),
    }
    cp1 = _proxy.checkpoint_intent(cp1_req)

    if not cp1["proceed"]:
        return {
            "session_id":    session_id,
            "cp1":           cp1,
            "cp2":           None,
            "agent_output":  None,
            "final_decision":cp1["decision"],
            "summary": (
                f"REQUEST {cp1['decision']} at Checkpoint 1. "
                f"Agent A was never reached. "
                f"Audit ID: {cp1['audit_id']}"
            ),
        }

    # Simulate Agent A
    agent_output = simulate_agent_response(
        agent_id        = request.agent_id,
        task_description= request.task_description,
        trigger_type    = request.trigger_type,
        scenario_hint   = request.scenario_hint,
    )

    cp2 = _proxy.checkpoint_output(
        session_id             = session_id,
        output                 = agent_output,
        actions_actually_taken = [a.get("action","") for a in request.requested_actions],
    )

    return {
        "session_id":    session_id,
        "cp1":           cp1,
        "cp2":           cp2,
        "agent_output":  agent_output,
        "final_decision":cp2["decision"],
        "approved_output":cp2["approved_output"],
        "summary": (
            f"CP1: {cp1['decision']} | CP2: {cp2['decision']}. "
            f"Audit ID: {cp1['audit_id']}"
        ),
    }


@app.post(
    "/proxy/checkpoint1",
    tags=["proxy"],
    summary="Checkpoint 1 — evaluate agent intent before reaching Agent A",
)
def proxy_checkpoint1(request: ProxyInterceptRequest):
    """
    Run only Checkpoint 1 (intent evaluation). Use this for testing individual
    scenarios without triggering Agent A simulation.
    """
    import uuid as _uuid
    session_id = request.timestamp and _proxy and str(_uuid.uuid4()) or str(_uuid.uuid4())
    cp1_req = {
        "session_id":        session_id,
        "agent_id":          request.agent_id,
        "caller_id":         request.caller_id,
        "task_description":  request.task_description,
        "requested_actions": request.requested_actions,
        "trigger_type":      request.trigger_type,
        "timestamp":         request.timestamp or __import__("datetime").datetime.now(
                                 __import__("datetime").timezone.utc).isoformat(),
    }
    return _proxy.checkpoint_intent(cp1_req)


@app.post(
    "/proxy/checkpoint2",
    tags=["proxy"],
    summary="Checkpoint 2 — evaluate Agent A output before reaching user",
)
def proxy_checkpoint2(request: ProxyOutputRequest):
    """
    Run only Checkpoint 2 (output evaluation). Requires a valid ``session_id``
    from a previous Checkpoint 1 call.
    """
    return _proxy.checkpoint_output(
        session_id             = request.session_id,
        output                 = request.output,
        actions_actually_taken = request.actions_actually_taken,
    )


@app.get(
    "/proxy/sessions",
    tags=["proxy"],
    summary="List all proxy sessions with both checkpoint results",
)
def proxy_sessions():
    """Returns all active and completed proxy sessions, most recent first."""
    sessions = sorted(
        _SESSIONS.values(),
        key=lambda s: s.get("created_at", ""),
        reverse=True,
    )
    return {"count": len(sessions), "sessions": sessions}


@app.delete(
    "/proxy/sessions",
    tags=["proxy"],
    summary="Clear all proxy sessions from memory",
)
def proxy_sessions_clear():
    """Clears the in-memory session store. Useful for demo resets."""
    count = len(_SESSIONS)
    _SESSIONS.clear()
    log.info("proxy_sessions_cleared", count=count)
    return {"cleared": count, "message": f"Cleared {count} session(s)"}


@app.get(
    "/proxy/sessions/{session_id}",
    tags=["proxy"],
    summary="Get full detail for a single proxy session",
)
def proxy_session_detail(session_id: str):
    """Returns the complete audit trail for one session including both checkpoints."""
    s = _SESSIONS.get(session_id)
    if not s:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return s


@app.get(
    "/proxy/pending-escalations",
    tags=["proxy"],
    summary="List sessions awaiting senior approval",
)
def proxy_pending_escalations():
    """Returns all sessions currently in ESCALATE status."""
    pending = [
        s for s in _SESSIONS.values()
        if s.get("status") == "escalation_pending"
    ]
    return {"count": len(pending), "pending": pending}


@app.post(
    "/proxy/approve-escalation",
    tags=["proxy"],
    summary="Approve a pending escalation",
)
def proxy_approve_escalation(request: EscalationRequest):
    """
    Approve a pending escalation. Marks the session as approved and allows
    the request to proceed (Agent A simulation runs on approval).
    """
    s = _SESSIONS.get(request.session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    if s.get("status") != "escalation_pending":
        raise HTTPException(status_code=400, detail=f"Session is not in escalation state (status: {s['status']})")
    s["status"]       = "approved"
    s["approved_by"]  = request.approver_id
    s["approval_notes"] = request.notes
    s["approved_at"]  = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).isoformat()
    log.info("escalation_approved", session_id=request.session_id, approver=request.approver_id)
    return {"status": "approved", "session_id": request.session_id, "approved_by": request.approver_id}


@app.get(
    "/proxy/scenarios",
    tags=["proxy"],
    summary="List all scenario library entries",
)
def proxy_scenarios_list():
    """Returns the full Trust Sentry scenario library (25 real consulting scenarios)."""
    return {"count": len(SCENARIO_LIBRARY), "scenarios": SCENARIO_LIBRARY}


@app.post(
    "/proxy/scenarios/{scenario_key}/run",
    tags=["proxy"],
    summary="Run a named scenario from the library through Checkpoint 1",
)
def proxy_scenario_run(scenario_key: str):
    """
    Look up a scenario by key and run it through Checkpoint 1.
    Returns the full CP1 result so callers can compare to expected_cp1.
    """
    req = scenario_to_checkpoint_request(scenario_key)
    if not req:
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_key}' not found")
    result = _proxy.checkpoint_intent(req)
    scenario_meta = SCENARIO_LIBRARY.get(scenario_key, {})
    return {
        "scenario_key":    scenario_key,
        "scenario_title":  scenario_meta.get("title", scenario_key),
        "expected_cp1":    scenario_meta.get("expected_cp1", "—"),
        "actual_decision": result.get("decision", "—"),
        "passed":          result.get("decision", "") == scenario_meta.get("expected_cp1", ""),
        "cp1":             result,
    }


@app.post(
    "/proxy/reject-escalation",
    tags=["proxy"],
    summary="Reject a pending escalation",
)
def proxy_reject_escalation(request: EscalationRequest):
    """Reject a pending escalation. The original request will not proceed."""
    s = _SESSIONS.get(request.session_id)
    if not s:
        raise HTTPException(status_code=404, detail="Session not found")
    s["status"]      = "rejected"
    s["rejected_by"] = request.approver_id
    s["reject_notes"] = request.notes
    s["rejected_at"] = __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc).isoformat()
    log.info("escalation_rejected", session_id=request.session_id, rejector=request.approver_id)
    return {"status": "rejected", "session_id": request.session_id, "rejected_by": request.approver_id}


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("trust_agent.api.main:app", host="0.0.0.0", port=port, reload=True)
