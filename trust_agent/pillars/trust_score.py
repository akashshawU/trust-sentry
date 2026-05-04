"""Pillar 1: Trust Score — composite metric aggregating all pillar scores."""

from pydantic import BaseModel


class TrustScoreInput(BaseModel):
    privacy: float
    access_control: float
    fairness: float
    explainability: float
    security: float
    regulatory_compliance: float
    operational_resilience: float


class TrustScoreResult(BaseModel):
    score: float
    grade: str
    breakdown: dict[str, float]


# Default equal weights for all pillars
DEFAULT_WEIGHTS: dict[str, float] = {
    "privacy": 1.0,
    "access_control": 1.0,
    "fairness": 1.0,
    "explainability": 1.0,
    "security": 1.0,
    "regulatory_compliance": 1.0,
    "operational_resilience": 1.0,
}


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def compute_trust_score(
    inputs: TrustScoreInput,
    weights: dict[str, float] | None = None,
) -> TrustScoreResult:
    """Compute a weighted composite trust score from individual pillar scores."""
    w = weights or DEFAULT_WEIGHTS
    breakdown = inputs.model_dump()
    total_weight = sum(w.get(k, 1.0) for k in breakdown)
    weighted_sum = sum(v * w.get(k, 1.0) for k, v in breakdown.items())
    score = round(weighted_sum / total_weight, 2)
    return TrustScoreResult(score=score, grade=_grade(score), breakdown=breakdown)
