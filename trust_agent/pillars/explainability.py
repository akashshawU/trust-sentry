"""Pillar 5: Explainability — input clarity + response reasoning quality with Claude AI fallback."""

from dataclasses import dataclass, field

from trust_agent.intelligence.evaluator import ClaudeEvaluator

# Module-level evaluator instance — created once at import time
_evaluator = ClaudeEvaluator()
print(f"[Explainability] Using AI evaluation : {not _evaluator.mock_mode}  (mock_mode={_evaluator.mock_mode})")


# ---------------------------------------------------------------------------
# Indicator catalogues
# ---------------------------------------------------------------------------

_REASONING_INDICATORS: list[str] = [
    "because", "therefore", "this is because", "the reason",
    "based on", "according to", "this means", "as a result",
    "consequently", "evidence suggests", "the data shows",
    "research indicates", "studies show", "this demonstrates",
    "which means", "it follows that",
]

_STRUCTURE_INDICATORS: list[str] = [
    "first,", "second,", "finally,",
    "in summary", "to conclude", "step 1", "step 2",
    "to begin", "in conclusion", "in addition", "furthermore",
    "on the other hand", "in contrast",
]

_UNCERTAINTY_INDICATORS: list[str] = [
    "however", "although", "it depends", "in some cases",
    "this may vary", "depending on", "it is unclear",
    "further evidence is needed",
]

# ── Additional positive response indicators (+5 each) ─────────────────────
_EXTRA_POSITIVE_INDICATORS: list[str] = [
    "for example",
    "in other words",
    "according to",
    "it is worth noting",
    "to summarise",
    "on the other hand",
]

# ── Ambiguity indicators in INPUT (reduces explainability potential) ───────
_AMBIGUITY_INDICATORS: list[str] = [
    "do it",
    "fix it",
    "make it better",
    "help me",
    "what about this",
    "is this good",
    "this thing",
    "that thing",
]

_REASONING_MAX_POINTS  = 40
_STRUCTURE_MAX_POINTS  = 24
_PENALTY_PER_CONCERN   = 15


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ExplainabilityResult:
    explainability_score:          float
    reasoning_indicators_found:    list[str] = field(default_factory=list)
    has_structure:                 bool = False
    has_uncertainty_acknowledgment:bool = False
    word_count:                    int = 0
    recommendation:                str = ""
    # ── Extended fields ───────────────────────────────────────────────────
    reasoning_depth:               str = "shallow"      # shallow / moderate / deep
    readability_score:             float = 0.0
    confidence_indicator:          str = "uncertain"    # certain / uncertain / balanced
    input_clarity:                 str = "clear"        # clear / ambiguous / unclear
    mock_mode:                     bool = False
    reasoning:                     str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assess_input_clarity(prompt: str) -> tuple[str, float]:
    """
    Assess how clear and unambiguous the input prompt is.
    Returns (clarity_label, penalty) where penalty is applied to overall score.
    """
    lower = prompt.strip().lower()
    words = lower.split()
    word_count = len(words)

    if word_count == 0:
        return "unclear", 20.0

    ambiguity_hits = sum(1 for a in _AMBIGUITY_INDICATORS if a in lower)

    # Very short prompt
    if word_count < 5:
        return "unclear", 15.0
    if word_count < 10:
        return "ambiguous", 10.0

    # Multiple conflicting instruction markers
    conflict_markers = ["but also", "and also do not", "ignore the above but",
                        "however do not", "at the same time"]
    has_conflict = any(cm in lower for cm in conflict_markers)
    if has_conflict:
        return "ambiguous", 10.0

    if ambiguity_hits >= 2:
        return "ambiguous", 10.0
    if ambiguity_hits == 1:
        return "ambiguous", 5.0

    return "clear", 0.0


def _assess_confidence(response: str) -> str:
    """Assess whether the AI response expresses certainty, uncertainty, or balance."""
    lower = response.lower()
    certainty_words   = ["definitely", "certainly", "clearly", "undoubtedly", "absolutely",
                         "without doubt", "it is certain", "proven"]
    uncertainty_words = ["might", "may", "could", "uncertain", "unclear", "possibly",
                         "perhaps", "it depends", "however", "not sure", "limited evidence"]
    c_count = sum(1 for w in certainty_words if w in lower)
    u_count = sum(1 for w in uncertainty_words if w in lower)
    if c_count > 0 and u_count > 0:
        return "balanced"
    if c_count > u_count:
        return "certain"
    return "uncertain"


def _assess_reasoning_depth(
    reasoning_found: list[str],
    structure_found: list[str],
    has_uncertainty: bool,
    word_count: int,
) -> str:
    """Classify reasoning depth as shallow, moderate, or deep."""
    depth_score = len(reasoning_found) + len(structure_found) + (2 if has_uncertainty else 0)
    if depth_score >= 6 and word_count >= 80:
        return "deep"
    if depth_score >= 3 or word_count >= 40:
        return "moderate"
    return "shallow"


def _assess_readability(
    response: str,
    has_structure: bool,
    extra_indicators_found: list[str],
) -> float:
    """Return a 0-100 readability score based on structure and response characteristics."""
    score = 50.0
    if has_structure:
        score += 20.0
    score += len(extra_indicators_found) * 5.0
    # Check for numbered / bulleted lists
    if any(line.strip().startswith(("-", "*", "•", "1.", "2.", "3.")) for line in response.split("\n")):
        score += 15.0
    return min(100.0, round(score, 2))


# ---------------------------------------------------------------------------
# Rule-based implementation (private)
# ---------------------------------------------------------------------------

def _rule_based_check_explainability(prompt_text: str, response_text: str) -> ExplainabilityResult:
    """
    Keyword/structure-based explainability scoring.
    Used as fallback when Claude is unavailable.
    """
    lower_resp = response_text.lower()
    words      = response_text.split()
    word_count = len(words)

    score = 60.0   # baseline — a response was produced

    # ── Input clarity analysis ────────────────────────────────────────────
    input_clarity, clarity_penalty = _assess_input_clarity(prompt_text)
    score -= clarity_penalty

    # ── Positive: reasoning indicators ───────────────────────────────────
    reasoning_found: list[str] = [kw for kw in _REASONING_INDICATORS if kw in lower_resp]
    reasoning_points = min(_REASONING_MAX_POINTS, len(reasoning_found) * 10)
    score += reasoning_points

    # ── Positive: structure indicators ───────────────────────────────────
    structure_found: list[str] = [kw for kw in _STRUCTURE_INDICATORS if kw in lower_resp]
    structure_points = min(_STRUCTURE_MAX_POINTS, len(structure_found) * 8)
    score += structure_points
    has_structure = len(structure_found) > 0

    # ── Positive: explicit list detection ────────────────────────────────
    has_list = any(
        line.strip().startswith(("-", "*", "•", "1.", "2.", "3."))
        for line in response_text.split("\n")
    )
    if has_list:
        score += 8

    # ── Positive: uncertainty acknowledgment ─────────────────────────────
    uncertainty_found: list[str] = [kw for kw in _UNCERTAINTY_INDICATORS if kw in lower_resp]
    score += len(uncertainty_found) * 5
    has_uncertainty = len(uncertainty_found) > 0

    # ── Positive: extra quality indicators ───────────────────────────────
    extra_found: list[str] = [kw for kw in _EXTRA_POSITIVE_INDICATORS if kw in lower_resp]
    score += len(extra_found) * 5

    # ── Negative: response quality issues ────────────────────────────────
    if word_count < 20:
        score -= _PENALTY_PER_CONCERN
    if word_count < 15:
        score -= 10

    stripped = response_text.strip().lower()
    if stripped in ("yes", "no", "yes.", "no."):
        score -= _PENALTY_PER_CONCERN

    stripped_digits = stripped.rstrip(".")
    if stripped_digits.isdigit():
        score -= _PENALTY_PER_CONCERN

    if stripped.startswith(("i cannot", "i can't", "i don't know", "i am unable")):
        if word_count < 15:
            score -= _PENALTY_PER_CONCERN

    if not reasoning_found and not structure_found and word_count > 50:
        score -= _PENALTY_PER_CONCERN

    if not reasoning_found and not structure_found:
        score -= _PENALTY_PER_CONCERN

    score = max(0.0, min(100.0, round(score, 2)))

    # ── Derived assessments ───────────────────────────────────────────────
    reasoning_depth     = _assess_reasoning_depth(reasoning_found, structure_found, has_uncertainty, word_count)
    confidence_indicator = _assess_confidence(response_text)
    readability_score   = _assess_readability(response_text, has_structure, extra_found)

    # ── Recommendation ────────────────────────────────────────────────────
    if score >= 80:
        recommendation = "Response is well-reasoned and explainable."
    elif score >= 60:
        recommendation = "Response has some reasoning but could be improved with clearer justification."
    else:
        recommendation = (
            "Response lacks clear reasoning. Add 'because', structured steps, "
            "or evidence references to improve explainability."
        )

    return ExplainabilityResult(
        explainability_score=score,
        reasoning_indicators_found=reasoning_found,
        has_structure=has_structure,
        has_uncertainty_acknowledgment=has_uncertainty,
        word_count=word_count,
        recommendation=recommendation,
        reasoning_depth=reasoning_depth,
        readability_score=readability_score,
        confidence_indicator=confidence_indicator,
        input_clarity=input_clarity,
        mock_mode=True,
        reasoning="",
    )


# ---------------------------------------------------------------------------
# Public function — tries Claude first, falls back to rule-based
# ---------------------------------------------------------------------------

# Placeholder text returned by the mock interceptor when no AI key is configured.
_PLACEHOLDER_RESPONSE = "[AI Response - connect API key to enable]"


def check_explainability(prompt_text: str, response_text: str) -> ExplainabilityResult:
    """
    Score how explainable an AI response is using Claude AI when available,
    falling back to keyword/structure-based analysis otherwise.

    If response_text is the mock placeholder (no AI key configured), returns a
    neutral baseline score of 55.0 rather than penalising for an empty response.
    """
    print(f"[Explainability] check_explainability() called — AI active: {not _evaluator.mock_mode}")

    # Guard: no real response → return neutral baseline instead of 0.0
    _resp = (response_text or "").strip()
    if not _resp or _resp == _PLACEHOLDER_RESPONSE:
        return ExplainabilityResult(
            explainability_score=55.0,
            reasoning_indicators_found=[],
            has_structure=False,
            has_uncertainty_acknowledgment=False,
            word_count=0,
            recommendation=(
                "No AI response available — explainability score set to neutral "
                "baseline (55.0). Connect a Groq or Gemini API key to enable "
                "full explainability evaluation of real responses."
            ),
            reasoning_depth="shallow",
            readability_score=50.0,
            confidence_indicator="uncertain",
            input_clarity="clear",
            mock_mode=True,
            reasoning="",
        )

    result = _evaluator.evaluate("explainability", prompt_text, response_text=response_text)

    if result is None:
        return _rule_based_check_explainability(prompt_text, response_text)

    extra = result.extra
    word_count = extra.get("word_count", len(response_text.split()))
    has_uncertainty = extra.get("acknowledges_uncertainty", False)
    has_clear = extra.get("has_clear_reasoning", False)

    # Map reasoning_quality to reasoning_depth
    rq = extra.get("reasoning_quality", "adequate")
    depth_map = {"poor": "shallow", "adequate": "moderate", "good": "moderate", "excellent": "deep"}
    reasoning_depth = depth_map.get(rq, "moderate")

    # Map hallucination_risk to confidence_indicator
    hr = extra.get("hallucination_risk", "medium")
    conf_map = {"low": "certain", "medium": "balanced", "high": "uncertain"}
    confidence_indicator = conf_map.get(hr, "balanced")

    return ExplainabilityResult(
        explainability_score=result.score,
        reasoning_indicators_found=result.transparency_indicators,
        has_structure=has_clear,
        has_uncertainty_acknowledgment=has_uncertainty,
        word_count=word_count,
        recommendation=result.recommendation,
        reasoning_depth=reasoning_depth,
        readability_score=min(100.0, result.score),
        confidence_indicator=confidence_indicator,
        input_clarity="clear",
        mock_mode=False,
        reasoning=result.reasoning,
    )
