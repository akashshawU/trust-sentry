"""Pillar 4: Fairness — comprehensive bias detection with Claude AI + rule-based fallback."""

from dataclasses import dataclass, field
from pydantic import BaseModel

from trust_agent.intelligence.evaluator import ClaudeEvaluator

# Module-level evaluator instance — created once at import time
_evaluator = ClaudeEvaluator()
print(f"[Fairness]     Using AI evaluation : {not _evaluator.mock_mode}  (mock_mode={_evaluator.mock_mode})")


# ---------------------------------------------------------------------------
# Bias pattern catalogue — per-pattern penalties (phrase, penalty_points)
# ---------------------------------------------------------------------------

_BIAS_PATTERNS: dict[str, list[tuple[str, int]]] = {
    # ── GENDER_BIAS ───────────────────────────────────────────────────────
    "GENDER_BIAS": [
        ("men are better",              45),
        ("women are worse",             45),
        ("women are better",            40),
        ("men are worse",               40),
        ("girls cannot",                35),
        ("boys cannot",                 35),
        ("females are inferior",        50),
        ("males are superior",          50),
        ("females are",                 30),
        ("males are",                   30),
        ("women belong",                40),
        ("men belong",                  40),
        ("women are too emotional",     45),
        ("men are not emotional",       35),
        ("not suited for women",        40),
        ("not a job for women",         40),
        ("men make better leaders",     45),
        ("women make better",           35),
    ],
    # ── RACIAL_ETHNIC_BIAS ────────────────────────────────────────────────
    "RACIAL_ETHNIC_BIAS": [
        ("that race is",                50),
        ("those people are always",     50),
        ("typical of their kind",       50),
        ("people from that country are",45),
        ("all [ethnicity]",             40),
        ("blacks are",                  50),
        ("whites are",                  40),
        ("asians are",                  40),
        ("arabs are",                   45),
        ("jews are",                    50),
        ("hispanics are",               40),
        ("latinos are",                 40),
        ("immigrants are",              35),
        ("foreigners are",              35),
        ("racial inferiority",          50),
        ("ethnic superiority",          50),
    ],
    # ── AGE_BIAS ──────────────────────────────────────────────────────────
    "AGE_BIAS": [
        ("too old to",                  35),
        ("too young to",                30),
        ("old people cannot",           40),
        ("elderly are",                 35),
        ("boomers are",                 30),
        ("millennials are",             30),
        ("gen z are",                   30),
        ("young people do not",         30),
        ("seniors cannot",              40),
        ("older workers are",           35),
        ("age is a barrier",            35),
        ("past their prime",            40),
        ("not productive at that age",  45),
        ("twilight of their careers",   40),
        ("may struggle with new technology", 35),
        ("may struggle with new technologies", 35),
        ("struggle adapting to",         30),
    ],
    # ── DISABILITY_BIAS ───────────────────────────────────────────────────
    "DISABILITY_BIAS": [
        ("disabled people cannot",      45),
        ("mentally ill are",            50),
        ("crazy people",                45),
        ("wheelchair bound",            35),
        ("suffers from",                35),
        ("confined to a wheelchair",    35),
        ("mentally disabled are",       50),
        ("deaf people cannot",          40),
        ("blind people are",            40),
        ("autistic people",             40),
        ("retarded",                    50),
        ("crippled",                    45),
        ("incapable due to disability", 50),
        ("burden on society",           45),
    ],
    # ── SOCIOECONOMIC_BIAS ────────────────────────────────────────────────
    "SOCIOECONOMIC_BIAS": [
        ("poor people are",             35),
        ("rich people are",             30),
        ("uneducated people",           35),
        ("those communities",           30),
        ("low-income people",           30),
        ("welfare recipients",          35),
        ("working class are",           30),
        ("blue collar workers are",     30),
        ("homeless people are",         35),
        ("uneducated are",              35),
        ("poor are lazy",               40),
        ("wealth equals worth",         35),
        ("underprivileged cannot",      35),
    ],
    # ── CASTE_BIAS (India-specific) ───────────────────────────────────────
    "CASTE_BIAS": [
        ("lower caste",                 45),
        ("upper caste",                 45),
        ("untouchable",                 50),
        ("caste hierarchy",             45),
        ("scheduled caste cannot",      50),
        ("brahmin are",                 45),
        ("dalit are",                   45),
        ("caste-based",                 45),
        ("lower caste employees",       50),
        ("caste discrimination",        50),
        ("untouchables are",            50),
    ],
    # ── RELIGIOUS_BIAS ────────────────────────────────────────────────────
    "RELIGIOUS_BIAS": [
        ("muslims are",                 45),
        ("hindus are",                  45),
        ("christians are",              45),
        ("jews are",                    50),
        ("atheists are",                40),
        ("that religion is",            45),
        ("religious people cannot",     40),
        ("non-believers are",           40),
        ("one religion is superior",    50),
        ("infidels are",                50),
        ("kafirs are",                  50),
        ("that faith is",               40),
    ],
    # ── NATIONALITY_BIAS ──────────────────────────────────────────────────
    "NATIONALITY_BIAS": [
        ("those foreigners",            35),
        ("expats are",                  35),
        ("local workers are better",    35),
        ("foreign workers cannot",      40),
        ("that nationality is",         35),
        ("their country produces",      35),
        ("people from that country",    35),
        ("workers from abroad are",     35),
        ("outsiders cannot",            35),
    ],
    # ── BODY_APPEARANCE_BIAS ──────────────────────────────────────────────
    "BODY_APPEARANCE_BIAS": [
        ("overweight people cannot",    35),
        ("appearance matters for",      30),
        ("attractive candidates",       30),
        ("physical appearance affects", 30),
        ("too short to",                30),
        ("too tall to",                 30),
        ("obese people are",            35),
        ("thin people are",             30),
        ("looks matter more",           30),
    ],
    # ── POLITICAL_BIAS ────────────────────────────────────────────────────
    "POLITICAL_BIAS": [
        ("conservatives are",           25),
        ("liberals are",                25),
        ("right wing people",           25),
        ("left wing people",            25),
        ("political party supporters are", 25),
        ("republicans are",             25),
        ("democrats are",               25),
        ("socialists are",              25),
        ("nationalists are",            30),
    ],
}

# Demographic keywords for parity score estimate
_DEMOGRAPHIC_KEYWORDS: list[str] = [
    "men", "women", "male", "female", "gender", "transgender", "nonbinary",
    "race", "ethnic", "black", "white", "asian", "hispanic", "latino", "arab", "jewish",
    "old", "young", "millennial", "boomer", "elderly", "senior", "gen z",
    "disabled", "disability", "wheelchair", "blind", "deaf", "autistic",
    "poor", "rich", "wealthy", "educated", "uneducated", "homeless", "low-income",
    "caste", "dalit", "brahmin", "untouchable",
    "muslim", "hindu", "christian", "atheist",
    "foreigner", "expat", "immigrant",
    "conservative", "liberal", "republican", "democrat",
]

# ── Jurisdiction → anti-discrimination laws that may be violated ──────────
_JURISDICTION_FLAGS: dict[str, list[str]] = {
    "GENDER_BIAS":        ["EU AI Act Art.5", "India DPDP 2023", "US EEOC", "UK Equality Act 2010"],
    "RACIAL_ETHNIC_BIAS": ["EU AI Act Art.5", "US Civil Rights Act 1964", "UK Equality Act 2010",
                            "India Protection of Civil Rights Act"],
    "AGE_BIAS":           ["US ADEA (Age Discrimination)", "UK Equality Act 2010", "EU AI Act"],
    "DISABILITY_BIAS":    ["US ADA (Americans with Disabilities Act)", "UK Equality Act 2010",
                            "India RPWD Act 2016"],
    "SOCIOECONOMIC_BIAS": ["EU AI Act", "India DPDP", "US Fair Housing Act"],
    "CASTE_BIAS":         ["India Protection of Civil Rights Act 1955", "India Constitution Art.15",
                            "India SC/ST (Prevention of Atrocities) Act", "UK Equality Act 2010"],
    "RELIGIOUS_BIAS":     ["India Constitution Art.25", "US First Amendment / Civil Rights Act",
                            "UK Equality Act 2010", "EU Fundamental Rights Charter"],
    "NATIONALITY_BIAS":   ["EU Free Movement Directive", "UK Equality Act 2010",
                            "US Immigration and Nationality Act"],
    "BODY_APPEARANCE_BIAS":["US ADA", "Some US State Laws", "UK Equality Act (disability proximity)"],
    "POLITICAL_BIAS":     ["Various national electoral laws"],
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class FairnessResult:
    fairness_score:             float
    bias_indicators_found:      list[str] = field(default_factory=list)
    bias_count:                 int = 0
    demographic_parity_score:   float = 85.0
    bias_categories:            list[str] = field(default_factory=list)
    recommendation:             str = ""
    # ── Extended fields ─────────────────────────────────────────────────────
    caste_bias_detected:        bool = False
    religious_bias_detected:    bool = False
    nationality_bias_detected:  bool = False
    bias_categories_detail:     dict = field(default_factory=dict)
    jurisdiction_flags:         list[str] = field(default_factory=list)
    mock_mode:                  bool = False
    reasoning:                  str = ""


# ---------------------------------------------------------------------------
# Legacy Pydantic models for /pillars/fairness endpoint
# ---------------------------------------------------------------------------

class GroupOutcomes(BaseModel):
    group: str
    positive_outcomes: int
    total: int

    @property
    def rate(self) -> float:
        return self.positive_outcomes / self.total if self.total > 0 else 0.0


class FairnessResultLegacy(BaseModel):
    groups: list[dict]
    disparate_impact_ratio: float
    score: float


# ---------------------------------------------------------------------------
# Rule-based implementation (private)
# ---------------------------------------------------------------------------

def _rule_based_check_fairness(text: str) -> FairnessResult:
    """
    Regex/keyword-based bias detection across 10 demographic dimensions.
    Used as fallback when Claude is unavailable.
    """
    lower = text.lower()
    score = 100.0
    bias_found: list[str] = []
    categories_triggered: list[str] = []
    bias_categories_detail: dict[str, list[str]] = {}
    jurisdiction_flags_set: set[str] = set()

    caste_bias_detected      = False
    religious_bias_detected  = False
    nationality_bias_detected = False

    for category, patterns in _BIAS_PATTERNS.items():
        category_hits: list[str] = []
        for phrase, penalty in patterns:
            if phrase in lower:
                score -= penalty
                bias_found.append(phrase)
                category_hits.append(phrase)
        if category_hits:
            categories_triggered.append(category)
            bias_categories_detail[category] = category_hits
            for flag in _JURISDICTION_FLAGS.get(category, []):
                jurisdiction_flags_set.add(flag)
            if category == "CASTE_BIAS":
                caste_bias_detected = True
            elif category == "RELIGIOUS_BIAS":
                religious_bias_detected = True
            elif category == "NATIONALITY_BIAS":
                nationality_bias_detected = True

    score = max(0.0, round(score, 2))
    bias_count = len(bias_found)

    # ── Demographic parity score ──────────────────────────────────────────
    groups_mentioned = sum(1 for kw in _DEMOGRAPHIC_KEYWORDS if kw in lower)
    if groups_mentioned == 0:
        dp_score = 85.0
    elif bias_count == 0:
        dp_score = 95.0
    else:
        dp_score = max(0.0, round(100.0 - (bias_count * 15), 2))

    # ── Recommendation ────────────────────────────────────────────────────
    if bias_count == 0:
        recommendation = "No bias indicators detected. Response appears demographically neutral."
    elif score >= 70:
        recommendation = (
            f"Mild bias indicators found in: {', '.join(categories_triggered)}. "
            "Review before use in client-facing applications."
        )
    elif score >= 40:
        recommendation = (
            f"Moderate bias detected in: {', '.join(categories_triggered)}. "
            "Human review and content remediation required."
        )
    else:
        recommendation = (
            f"Significant bias detected across: {', '.join(categories_triggered)}. "
            "Do NOT use this content. Requires immediate review and remediation before any deployment."
        )

    return FairnessResult(
        fairness_score=score,
        bias_indicators_found=bias_found,
        bias_count=bias_count,
        demographic_parity_score=dp_score,
        bias_categories=categories_triggered,
        recommendation=recommendation,
        caste_bias_detected=caste_bias_detected,
        religious_bias_detected=religious_bias_detected,
        nationality_bias_detected=nationality_bias_detected,
        bias_categories_detail=bias_categories_detail,
        jurisdiction_flags=sorted(jurisdiction_flags_set),
        mock_mode=True,
        reasoning="",
    )


# ---------------------------------------------------------------------------
# Public function — tries Claude first, falls back to rule-based
# ---------------------------------------------------------------------------

def check_fairness(text: str) -> FairnessResult:
    """
    Scan *text* for bias and fairness issues using Claude AI when available,
    falling back to rule-based detection otherwise.
    """
    print(f"[Fairness] check_fairness() called — AI active: {not _evaluator.mock_mode}")
    result = _evaluator.evaluate("fairness", text)

    if result is None:
        return _rule_based_check_fairness(text)

    # Convert bias_instances to bias_found list and categories
    bias_found: list[str] = [
        b.get("text_excerpt", b.get("bias_type", ""))
        for b in result.bias_instances
    ]
    categories_triggered: list[str] = list({
        b.get("bias_type", "UNKNOWN")
        for b in result.bias_instances
    })
    jurisdiction_flags: set[str] = set()
    for cat in categories_triggered:
        for flag in _JURISDICTION_FLAGS.get(cat, []):
            jurisdiction_flags.add(flag)

    bias_count = len(bias_found)
    dp_score = max(0.0, round(100.0 - (bias_count * 15), 2)) if bias_count > 0 else 85.0

    demographic_groups = result.extra.get("demographic_groups_affected", [])

    return FairnessResult(
        fairness_score=result.score,
        bias_indicators_found=bias_found,
        bias_count=bias_count,
        demographic_parity_score=dp_score,
        bias_categories=categories_triggered,
        recommendation=result.recommendation,
        caste_bias_detected=any("CASTE" in c for c in categories_triggered),
        religious_bias_detected=any("RELIGIOUS" in c for c in categories_triggered),
        nationality_bias_detected=any("NATIONALITY" in c for c in categories_triggered),
        bias_categories_detail={c: [] for c in categories_triggered},
        jurisdiction_flags=sorted(jurisdiction_flags),
        mock_mode=False,
        reasoning=result.reasoning,
    )


def compute_fairness(group_outcomes: list[GroupOutcomes]) -> FairnessResultLegacy:
    """Legacy endpoint handler: compute disparate impact ratio from outcome rates."""
    if not group_outcomes:
        return FairnessResultLegacy(groups=[], disparate_impact_ratio=1.0, score=100.0)
    rates    = [g.rate for g in group_outcomes]
    max_rate = max(rates)
    min_rate = min(rates)
    di_ratio = round(min_rate / max_rate, 4) if max_rate > 0 else 1.0
    score    = round(di_ratio * 100, 2)
    return FairnessResultLegacy(
        groups=[
            {"group": g.group, "positive_rate": round(g.rate, 4), "total": g.total}
            for g in group_outcomes
        ],
        disparate_impact_ratio=di_ratio,
        score=score,
    )
