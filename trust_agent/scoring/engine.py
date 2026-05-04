"""Trust Score Engine — aggregates all 8 pillar scores into a unified trust report."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog
from pydantic import BaseModel

from trust_agent.pillars.access_control import check_access
from trust_agent.pillars.explainability import check_explainability, _PLACEHOLDER_RESPONSE
from trust_agent.pillars.fairness import check_fairness
from trust_agent.pillars.operational_resilience import check_resilience
from trust_agent.pillars.privacy import analyze_and_anonymize as _privacy_analyze
from trust_agent.pillars.regulatory_compliance import check_compliance
from trust_agent.pillars.security import check_security
from trust_agent.pillars.trust_score import (
    TrustScoreInput,
    TrustScoreResult,
    compute_trust_score,
)

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# TrustScoreEngine
# ---------------------------------------------------------------------------

class TrustStatus(str, Enum):
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED   = "RED"


@dataclass
class TrustScore:
    reliability_score:    float
    privacy_score:        float
    security_score:       float
    access_score:         float
    fairness_score:       float
    explainability_score: float
    compliance_score:     float
    resilience_score:     float
    composite_score:      float
    status:               TrustStatus
    pillar_details:       dict = field(default_factory=dict)


# Composite weights — must sum to 1.0
_WEIGHTS = {
    "reliability":    0.10,
    "privacy":        0.22,
    "security":       0.22,
    "access":         0.12,
    "fairness":       0.10,
    "explainability": 0.08,
    "compliance":     0.12,
    "resilience":     0.04,
}


class TrustScoreEngine:
    """
    Scores an AI service call across all 8 trust dimensions using real pillar
    logic and returns a composite :class:`TrustScore`.

    Weights
    -------
    reliability 10% · privacy 22% · security 22% · access 12% ·
    fairness 10% · explainability 8% · compliance 12% · resilience 4%

    Status thresholds
    -----------------
    GREEN ≥ 85 · AMBER ≥ 55 · RED < 55
    """

    def score(self, log_entry: dict[str, Any]) -> TrustScore:
        """
        Compute a full :class:`TrustScore` from a log entry produced by
        :class:`~trust_agent.interceptor.TrustInterceptor`.

        Args:
            log_entry: Plain dict from ``LogEntry.model_dump()``.  Expected keys:
                ``metadata`` (dict), ``input_pii`` (dict), ``output_pii`` (dict),
                ``caller_id`` (str), ``service_name`` (str),
                ``_prompt`` (str, optional), ``_response`` (str, optional).
        """
        # ── Extract fields from log entry ──────────────────────────────────
        metadata     = log_entry.get("metadata") or {}
        caller_id    = log_entry.get("caller_id", "user")
        service_name = log_entry.get("service_name", "unknown")
        prompt_text  = log_entry.get("_prompt",   "")
        response_text= log_entry.get("_response", "[AI Response - connect API key to enable]")

        # ── Reliability (from interceptor: did the call succeed?) ──────────
        reliability = 0.0 if metadata.get("error") else 100.0

        # ── Privacy — severity-weighted penalty scoring via privacy pillar ──
        # Uses analyze_and_anonymize() directly so that:
        #   • Low-risk entities (LOCATION, DATE_TIME) don't crush the score
        #   • Custom India/ME PII (Aadhaar, PAN, Emirates ID) are detected
        #   • Empty text correctly returns 100.0 (clean) not 0.0
        _priv_result = _privacy_analyze(prompt_text)
        privacy = _priv_result.privacy_score

        # ── Security ──────────────────────────────────────────────────────
        sec_result  = check_security(prompt_text)
        security    = sec_result.security_score

        # ── Access Control ────────────────────────────────────────────────
        acc_result  = check_access(caller_id, resource=service_name, action="read")
        access      = acc_result.access_score

        # ── Fairness ──────────────────────────────────────────────────────
        fair_result = check_fairness(prompt_text)
        fairness    = fair_result.fairness_score

        # ── Explainability ────────────────────────────────────────────────
        expl_result    = check_explainability(prompt_text, response_text)
        explainability = expl_result.explainability_score
        # Safe neutral fallback: 0.0 with placeholder response means "no data",
        # not a real violation — use 55.0 so it doesn't distort the composite.
        if explainability == 0.0 and (
            not response_text or response_text.strip() == _PLACEHOLDER_RESPONSE
        ):
            explainability = 55.0

        # ── Compliance ────────────────────────────────────────────────────
        comp_result = check_compliance(prompt_text)
        compliance  = comp_result.compliance_score

        # ── Resilience ────────────────────────────────────────────────────
        res_result  = check_resilience(service_name)
        resilience  = res_result.resilience_score

        # ── Composite ─────────────────────────────────────────────────────
        composite = round(
            reliability    * _WEIGHTS["reliability"]
            + privacy      * _WEIGHTS["privacy"]
            + security     * _WEIGHTS["security"]
            + access       * _WEIGHTS["access"]
            + fairness     * _WEIGHTS["fairness"]
            + explainability * _WEIGHTS["explainability"]
            + compliance   * _WEIGHTS["compliance"]
            + resilience   * _WEIGHTS["resilience"],
            2,
        )

        status = self._derive_status(composite)

        # ── Pillar detail payload for API + dashboard ──────────────────────
        pillar_details = {
            "privacy": {
                "entity_count":     _priv_result.entity_count,
                "entity_types":     [e["entity_type"] for e in _priv_result.entities_found],
                "critical_entities":_priv_result.critical_entities,
                "risk_score":       _priv_result.risk_score,
                "recommendation":   _priv_result.recommendation,
                "entities_found":   _priv_result.entities_found[:20],  # cap for payload size
            },
            "security": {
                "threats_found":       sec_result.threats_found,
                "severity":            sec_result.severity,
                "threat_count":        sec_result.threat_count,
                "categories_triggered":sec_result.categories_triggered,
            },
            "access_control": {
                "role_detected":       acc_result.role_detected,
                "role_key":            acc_result.role_key,
                "action_permitted":    acc_result.action_permitted,
                "resource_sensitivity":acc_result.resource_sensitivity,
                "trust_level":         acc_result.trust_level,
                "risk_flags":          acc_result.risk_flags,
            },
            "fairness": {
                "bias_indicators_found":    fair_result.bias_indicators_found,
                "bias_categories":          fair_result.bias_categories,
                "demographic_parity_score": fair_result.demographic_parity_score,
                "caste_bias_detected":      fair_result.caste_bias_detected,
                "religious_bias_detected":  fair_result.religious_bias_detected,
                "nationality_bias_detected":fair_result.nationality_bias_detected,
                "jurisdiction_flags":       fair_result.jurisdiction_flags,
            },
            "explainability": {
                "reasoning_indicators_found":     expl_result.reasoning_indicators_found,
                "has_structure":                  expl_result.has_structure,
                "has_uncertainty_acknowledgment": expl_result.has_uncertainty_acknowledgment,
                "word_count":                     expl_result.word_count,
                "reasoning_depth":                expl_result.reasoning_depth,
                "input_clarity":                  expl_result.input_clarity,
                "confidence_indicator":           expl_result.confidence_indicator,
            },
            "compliance": {
                "violations_found":    comp_result.violations_found,
                "triggers_found":      comp_result.triggers_found,
                "overall_risk":        comp_result.overall_risk,
                "evidence_summary":    comp_result.evidence_summary,
                "jurisdictions_covered": comp_result.jurisdictions_covered,
            },
            "resilience": {
                "total_calls":        res_result.total_calls,
                "error_rate":         res_result.error_rate,
                "health_status":      res_result.health_status,
                "latency_vs_baseline":res_result.latency_vs_baseline,
            },
        }

        log.info(
            "trust_score_computed",
            caller_id=caller_id,
            service_name=service_name,
            reliability=reliability,
            privacy=privacy,
            security=security,
            access=access,
            fairness=fairness,
            explainability=explainability,
            compliance=compliance,
            resilience=resilience,
            composite=composite,
            status=status.value,
        )

        return TrustScore(
            reliability_score=reliability,
            privacy_score=privacy,
            security_score=security,
            access_score=access,
            fairness_score=fairness,
            explainability_score=explainability,
            compliance_score=compliance,
            resilience_score=resilience,
            composite_score=composite,
            status=status,
            pillar_details=pillar_details,
        )

    @staticmethod
    def _derive_status(composite: float) -> TrustStatus:
        if composite >= 85.0:
            return TrustStatus.GREEN
        if composite >= 55.0:
            return TrustStatus.AMBER
        return TrustStatus.RED


# ---------------------------------------------------------------------------
# Legacy trust report helpers (unchanged — used by /trust-report endpoint)
# ---------------------------------------------------------------------------

class TrustReport(BaseModel):
    model_id: str
    trust_score: TrustScoreResult
    pillar_scores: dict[str, float]
    recommendations: list[str]


SCORE_THRESHOLDS = {
    "privacy": 70.0, "access_control": 80.0, "fairness": 80.0,
    "explainability": 60.0, "security": 85.0,
    "regulatory_compliance": 75.0, "operational_resilience": 80.0,
}

RECOMMENDATIONS = {
    "privacy":               "Reduce PII exposure in model inputs/outputs and enforce data minimization.",
    "access_control":        "Review role assignments and tighten resource-action policies.",
    "fairness":              "Investigate demographic groups with low positive-outcome rates for bias.",
    "explainability":        "Provide feature importances and structured rationales for predictions.",
    "security":              "Harden prompt handling and add adversarial input filtering.",
    "regulatory_compliance": "Remediate non-compliant controls, starting with highest-risk frameworks.",
    "operational_resilience":"Address model drift, reduce error rates, and improve data quality.",
}


def generate_trust_report(
    model_id: str,
    pillar_scores: dict[str, float],
    weights: dict[str, float] | None = None,
) -> TrustReport:
    """Generate a full trust report for an AI model given its per-pillar scores."""
    inputs = TrustScoreInput(**pillar_scores)
    trust_score = compute_trust_score(inputs, weights=weights)
    recommendations = [
        RECOMMENDATIONS[pillar]
        for pillar, threshold in SCORE_THRESHOLDS.items()
        if pillar_scores.get(pillar, 100.0) < threshold
    ]
    log.info(
        "trust_report_generated",
        model_id=model_id, score=trust_score.score,
        grade=trust_score.grade, recommendations_count=len(recommendations),
    )
    return TrustReport(
        model_id=model_id,
        trust_score=trust_score,
        pillar_scores=pillar_scores,
        recommendations=recommendations,
    )
