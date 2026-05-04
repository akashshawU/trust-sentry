"""Pillar 7: Regulatory Compliance — 35+ framework-aware compliance checking with Claude AI + rule-based fallback."""

from dataclasses import dataclass, field
from pydantic import BaseModel

from trust_agent.intelligence.evaluator import ClaudeEvaluator

# Module-level evaluator instance — created once at import time
_evaluator = ClaudeEvaluator()
print(f"[Compliance]   Using AI evaluation : {not _evaluator.mock_mode}  (mock_mode={_evaluator.mock_mode})")


# ---------------------------------------------------------------------------
# Framework rule catalogue
# ---------------------------------------------------------------------------

COMPLIANCE_RULES: dict[str, dict] = {

    # ══════════════════════════════════════════════════════════════════════
    # GLOBAL / INTERNATIONAL
    # ══════════════════════════════════════════════════════════════════════
    "gdpr": {
        "name": "GDPR", "region": "EU",
        "triggers": [
            "personal data", "data subject", "consent", "right to erasure",
            "data breach", "processor", "controller", "legitimate interest",
        ],
        "violations": [
            "sell personal data", "share without consent",
            "retain indefinitely", "no privacy policy",
            "third party sharing", "cross border transfer",
        ],
        "critical_violations": ["sell personal data", "share without consent"],
        "weight": 0.18,
    },
    "eu_ai_act": {
        "name": "EU AI Act", "region": "EU",
        "triggers": [
            "high risk ai", "biometric", "critical infrastructure",
            "employment decision", "credit scoring", "law enforcement", "education access",
        ],
        "violations": [
            "social scoring", "real time biometric",
            "subliminal manipulation", "exploit vulnerability",
        ],
        "critical_violations": ["social scoring", "subliminal manipulation"],
        "weight": 0.16,
    },
    "iso_42001": {
        "name": "ISO 42001", "region": "Global",
        "triggers": [
            "ai system", "risk assessment", "governance",
            "accountability", "transparency", "audit",
        ],
        "violations": [
            "no documentation", "no oversight",
            "no risk assessment", "unmonitored ai",
        ],
        "critical_violations": ["no oversight", "unmonitored ai"],
        "weight": 0.14,
    },
    "nist_ai_rmf": {
        "name": "NIST AI RMF", "region": "Global",
        "triggers": [
            "trustworthy ai", "bias", "fairness",
            "explainability", "privacy", "security",
        ],
        "violations": [
            "unexplainable decision", "biased outcome",
            "privacy violation", "security breach",
        ],
        "critical_violations": ["privacy violation", "security breach"],
        "weight": 0.12,
    },
    "iso_27001": {
        "name": "ISO 27001", "region": "International",
        "triggers": [
            "information security", "data security", "security management",
            "confidentiality", "integrity", "availability", "isms",
            "security controls", "risk assessment", "incident management",
        ],
        "violations": [
            "no information security policy", "inadequate access controls",
            "no security incident process", "unencrypted sensitive data",
            "no risk assessment", "no business continuity",
            "third party security not managed", "no security awareness training",
        ],
        "critical_violations": ["unencrypted sensitive data"],
        "weight": 0.10,
    },
    "oecd_ai_principles": {
        "name": "OECD AI Principles", "region": "International",
        "triggers": [
            "ai policy", "responsible ai", "trustworthy ai",
            "ai governance", "human centred ai", "ai transparency",
            "ai accountability", "ai values", "ai safety", "ai ethics",
        ],
        "violations": [
            "ai harming human rights", "no inclusive ai",
            "ai without transparency", "no accountability for ai",
            "unsafe ai deployment", "ai discrimination",
            "no explainability", "no human oversight",
        ],
        "critical_violations": ["ai harming human rights", "unsafe ai deployment"],
        "weight": 0.08,
    },

    # ══════════════════════════════════════════════════════════════════════
    # EUROPEAN UNION (additional)
    # ══════════════════════════════════════════════════════════════════════
    "dora": {
        "name": "DORA (Digital Operational Resilience)", "region": "EU",
        "triggers": [
            "digital operational resilience", "ict risk", "third party ict",
            "financial entity", "incident reporting", "operational resilience",
            "ict services", "digital resilience testing",
        ],
        "violations": [
            "no ict risk management", "unreported ict incident",
            "no resilience testing", "no third party ict oversight",
            "no business continuity for ict",
        ],
        "critical_violations": ["unreported ict incident"],
        "weight": 0.10,
    },

    # ══════════════════════════════════════════════════════════════════════
    # INDIA
    # ══════════════════════════════════════════════════════════════════════
    "india_dpdp": {
        "name": "India DPDP Act 2023", "region": "India",
        "triggers": [
            "personal data", "data principal", "data fiduciary", "consent",
            "purpose limitation", "data localisation", "data breach",
            "processing personal data", "sensitive personal data",
            "children data", "grievance redressal", "data protection board",
        ],
        "violations": [
            "process without consent", "no purpose limitation",
            "collect more data than necessary",
            "transfer data outside india without approval",
            "process children data without guardian consent",
            "no breach notification", "no grievance officer appointed",
            "retain beyond purpose", "no data principal rights",
            "process sensitive data without explicit consent",
        ],
        "critical_violations": [
            "transfer data outside india without approval",
            "process children data without guardian consent",
            "no breach notification",
        ],
        "weight": 0.15,
    },
    "india_ai_guidelines_2025": {
        "name": "India AI Governance Guidelines 2025", "region": "India",
        "triggers": [
            "artificial intelligence", "ai system", "automated decision",
            "algorithmic", "machine learning", "deep learning", "generative ai",
            "large language model", "ai governance", "responsible ai",
            "ai risk", "digital india",
        ],
        "violations": [
            "no human oversight", "unexplainable ai decision",
            "biased ai system", "no accountability mechanism",
            "no transparency", "harm to data principal",
            "discriminatory ai outcome", "no grievance redressal for ai",
            "automated rejection without appeal",
            "no risk assessment for high risk ai",
        ],
        "critical_violations": ["biased ai system", "discriminatory ai outcome"],
        "weight": 0.12,
    },
    "rbi_free_ai": {
        "name": "RBI FREE-AI Framework", "region": "India - Financial",
        "triggers": [
            "banking", "financial services", "credit", "loan", "payment",
            "insurance", "investment", "rbi regulated", "financial institution",
            "nbfc", "bank customer data",
        ],
        "violations": [
            "no model explainability", "biased credit decision",
            "no customer consent for ai", "automated loan rejection without review",
            "no model validation", "unexplainable financial decision",
            "discriminatory financial ai", "no human override for ai decisions",
            "use customer data without consent", "no audit trail for financial ai",
        ],
        "critical_violations": [
            "biased credit decision", "discriminatory financial ai",
            "no audit trail for financial ai",
        ],
        "weight": 0.13,
    },

    # ══════════════════════════════════════════════════════════════════════
    # UNITED STATES
    # ══════════════════════════════════════════════════════════════════════
    "us_ccpa_cpra": {
        "name": "California CCPA / CPRA", "region": "USA - California",
        "triggers": [
            "california consumer", "personal information", "consumer rights",
            "opt out", "automated decision", "profiling",
            "sale of personal information", "sensitive personal information",
            "data broker", "right to know",
        ],
        "violations": [
            "sell personal information without opt-out",
            "no consumer rights disclosure",
            "automated decision without opt-out option",
            "no privacy policy", "share data without consumer knowledge",
            "process sensitive data without consent", "no right to deletion",
            "discriminatory ai treatment", "profile consumers without disclosure",
            "no response to consumer requests",
        ],
        "critical_violations": [
            "sell personal information without opt-out",
            "automated decision without opt-out option",
        ],
        "weight": 0.12,
    },
    "us_hipaa": {
        "name": "US HIPAA", "region": "USA - Healthcare",
        "triggers": [
            "patient data", "medical record", "health information", "phi",
            "protected health information", "healthcare ai", "clinical decision",
            "diagnostic ai", "patient privacy", "electronic health record", "ehr",
            "treatment history", "patients treatment", "patient treatment",
            "health data", "medical data", "clinical data",
        ],
        "violations": [
            "disclose phi without authorisation",
            "no hipaa compliance", "share patient data without consent",
            "process phi without safeguards", "no minimum necessary standard",
            "phi in ai training without de-identification",
            "breach of patient confidentiality",
            "no business associate agreement",
            "use phi for non-treatment purposes",
            "patient data sold to third parties",
            "targeted pharmaceutical advertisements",
            "use treatment history for marketing",
            "use patient data for advertising",
            "send targeted advertisements",
            "marketing using patient",
            "pharmaceutical advertisements",
        ],
        "critical_violations": [
            "disclose phi without authorisation",
            "patient data sold to third parties",
            "no business associate agreement",
            "targeted pharmaceutical advertisements",
            "pharmaceutical advertisements",
        ],
        "weight": 0.15,
    },
    "us_sox": {
        "name": "US SOX (Sarbanes-Oxley)", "region": "USA - Financial",
        "triggers": [
            "financial reporting", "audit", "internal control", "sox compliance",
            "material weakness", "financial statement", "executive certification",
            "public company", "sec filing", "quarterly report", "annual report",
        ],
        "violations": [
            "no audit trail", "falsify financial records", "no internal controls",
            "ai generated financial report without review",
            "no human oversight of financial ai", "destroy financial records",
            "misrepresent financial data", "no documentation of ai decisions",
            "bypass internal controls", "no segregation of duties",
        ],
        "critical_violations": [
            "falsify financial records", "no audit trail",
            "destroy financial records",
        ],
        "weight": 0.12,
    },
    "us_fcra": {
        "name": "US Fair Credit Reporting Act", "region": "USA - Financial",
        "triggers": [
            "credit decision", "credit score", "credit report", "adverse action",
            "consumer report", "credit bureau", "background check",
            "employment screening", "tenant screening", "credit underwriting",
        ],
        "violations": [
            "deny credit without adverse action notice",
            "use inaccurate credit data", "no consumer right to dispute",
            "automated credit denial without explanation",
            "discriminatory credit decision", "use protected class in credit decision",
            "no permissible purpose for credit check",
            "share credit data without consent",
        ],
        "critical_violations": [
            "discriminatory credit decision", "automated credit denial without explanation",
        ],
        "weight": 0.10,
    },
    "colorado_ai_act": {
        "name": "Colorado AI Act (2026)", "region": "USA - Colorado",
        "triggers": [
            "high risk ai", "consequential decision", "employment decision",
            "housing decision", "credit decision", "education access",
            "healthcare decision", "legal matter", "automated decision system",
        ],
        "violations": [
            "no impact assessment for high risk ai",
            "discriminatory automated decision", "no consumer disclosure",
            "no right to opt out", "no human review available",
            "algorithmic discrimination", "no documentation of high risk ai",
            "failure to notify of adverse decision",
        ],
        "critical_violations": [
            "discriminatory automated decision", "algorithmic discrimination",
        ],
        "weight": 0.10,
    },

    # ══════════════════════════════════════════════════════════════════════
    # UNITED KINGDOM
    # ══════════════════════════════════════════════════════════════════════
    "uk_ai_principles": {
        "name": "UK AI Regulation White Paper", "region": "United Kingdom",
        "triggers": [
            "artificial intelligence", "automated system", "machine learning",
            "algorithmic decision", "ai transparency", "ai safety", "ai accountability",
            "uk market", "british consumer", "ico regulation", "fca ai",
        ],
        "violations": [
            "no safety assessment", "unexplainable ai decision to uk consumer",
            "discriminatory ai outcome", "no accountability structure",
            "no redress mechanism", "ai causing harm without oversight",
            "no transparency about ai use", "bias against protected characteristic",
            "no human oversight for high stakes decision",
        ],
        "critical_violations": [
            "discriminatory ai outcome", "ai causing harm without oversight",
        ],
        "weight": 0.10,
    },
    "uk_gdpr": {
        "name": "UK GDPR", "region": "United Kingdom",
        "triggers": [
            "personal data", "data subject", "consent", "uk citizen data",
            "ico", "data controller", "legitimate interest", "data breach",
            "right to erasure", "data portability",
        ],
        "violations": [
            "process uk personal data without lawful basis",
            "transfer uk data outside uk without safeguards",
            "no consent for processing", "retain beyond purpose",
            "no data subject rights", "no breach notification within 72 hours",
            "automated decision without human review", "sell uk personal data",
        ],
        "critical_violations": [
            "sell uk personal data", "transfer uk data outside uk without safeguards",
        ],
        "weight": 0.12,
    },

    # ══════════════════════════════════════════════════════════════════════
    # ASIA PACIFIC
    # ══════════════════════════════════════════════════════════════════════
    "singapore_pdpa": {
        "name": "Singapore PDPA + AI Framework", "region": "Singapore",
        "triggers": [
            "singapore data", "pdpa", "personal data", "do not call",
            "data protection officer", "consent", "purpose limitation",
            "ai governance singapore", "pdpc", "data intermediary",
        ],
        "violations": [
            "collect without consent", "use beyond original purpose",
            "no data protection officer",
            "transfer outside singapore without protection",
            "no data accuracy maintenance", "no access and correction rights",
            "retain beyond purpose", "no data breach notification",
        ],
        "critical_violations": ["collect without consent"],
        "weight": 0.10,
    },
    "china_pipl": {
        "name": "China PIPL", "region": "China",
        "triggers": [
            "china personal data", "pipl", "chinese citizen data",
            "data localisation", "cross border transfer china",
            "algorithmic recommendation", "facial recognition china",
            "cyberspace administration", "sensitive personal information china",
        ],
        "violations": [
            "transfer china data overseas without approval",
            "process sensitive data without consent",
            "no data localisation for critical information",
            "algorithmic decision without transparency",
            "no right to explanation", "collect beyond necessity",
            "automated profiling without disclosure",
            "no separate consent for sensitive data",
        ],
        "critical_violations": ["transfer china data overseas without approval"],
        "weight": 0.10,
    },
    "south_korea_ai_act": {
        "name": "South Korea AI Framework Act", "region": "South Korea",
        "triggers": [
            "south korea ai", "korean ai system", "high impact ai",
            "ai transparency korea", "ai safety korea", "artificial intelligence act",
        ],
        "violations": [
            "no ai transparency disclosure",
            "high impact ai without safety review",
            "no human oversight for high impact ai",
            "ai causing harm without redress",
            "no risk management for high impact ai",
        ],
        "critical_violations": ["high impact ai without safety review"],
        "weight": 0.08,
    },

    # ══════════════════════════════════════════════════════════════════════
    # MIDDLE EAST — UAE
    # ══════════════════════════════════════════════════════════════════════
    "uae_pdpl": {
        "name": "UAE PDPL", "region": "UAE",
        "triggers": [
            "personal data", "data controller", "data subject rights",
            "consent", "uae residents", "data protection officer",
        ],
        "violations": [
            "sell personal data", "share without consent",
            "no data protection policy", "retain beyond purpose",
            "unauthorized cross-border transfer",
        ],
        "critical_violations": ["sell personal data", "share without consent"],
        "weight": 0.15,
    },
    "uae_ai_ethics": {
        "name": "UAE AI Ethics", "region": "UAE",
        "triggers": [
            "ai ethics", "human oversight", "ai transparency",
            "ai accountability", "uae ai strategy",
        ],
        "violations": [
            "no human oversight", "unexplained ai decision",
            "discriminatory ai", "no accountability mechanism",
        ],
        "critical_violations": ["discriminatory ai"],
        "weight": 0.12,
    },
    "uae_cybersecurity": {
        "name": "UAE Cybersecurity", "region": "UAE",
        "triggers": [
            "cybersecurity", "data breach", "encryption",
            "incident response", "uae sia",
        ],
        "violations": [
            "no encryption", "unpatched vulnerability",
            "no incident response plan", "data breach unreported",
        ],
        "critical_violations": ["data breach unreported"],
        "weight": 0.12,
    },
    "difc_dp": {
        "name": "DIFC DP Law", "region": "UAE",
        "triggers": [
            "difc", "data protection", "personal information",
            "data processor", "lawful basis",
        ],
        "violations": [
            "no lawful basis", "unauthorized processing",
            "no data retention policy", "breach not notified",
        ],
        "critical_violations": ["unauthorized processing"],
        "weight": 0.13,
    },
    "adgm_dp": {
        "name": "ADGM DP Regulations", "region": "UAE",
        "triggers": [
            "adgm", "abu dhabi global market", "personal data",
            "data subject", "privacy notice",
        ],
        "violations": [
            "no privacy notice", "unauthorized data sharing",
            "no consent mechanism", "data transferred without safeguards",
        ],
        "critical_violations": ["unauthorized data sharing"],
        "weight": 0.10,
    },

    # ══════════════════════════════════════════════════════════════════════
    # MIDDLE EAST — KSA
    # ══════════════════════════════════════════════════════════════════════
    "ksa_pdpl": {
        "name": "KSA PDPL", "region": "KSA",
        "triggers": [
            "personal data", "saudi data authority", "sdaia",
            "data subject consent", "saudi residents",
        ],
        "violations": [
            "sell personal data", "process without consent",
            "transfer outside ksa without approval", "retain beyond purpose",
            "no privacy policy",
        ],
        "critical_violations": [
            "sell personal data", "transfer outside ksa without approval",
        ],
        "weight": 0.15,
    },
    "ksa_ai_ethics": {
        "name": "KSA AI Ethics (SDAIA)", "region": "KSA",
        "triggers": [
            "ai ethics", "responsible ai", "ai governance",
            "saudi vision 2030", "ksa ai framework",
        ],
        "violations": [
            "biased algorithm", "no human oversight",
            "opaque ai decision", "no accountability",
        ],
        "critical_violations": ["biased algorithm"],
        "weight": 0.12,
    },
    "ksa_cybersecurity": {
        "name": "KSA Cybersecurity (NCA)", "region": "KSA",
        "triggers": [
            "nca", "cybersecurity", "essential cybersecurity controls",
            "critical national infrastructure", "cyber threat",
        ],
        "violations": [
            "no access control", "unencrypted sensitive data",
            "no vulnerability management", "incident not reported",
        ],
        "critical_violations": ["unencrypted sensitive data"],
        "weight": 0.12,
    },
    "sama_regulations": {
        "name": "SAMA Regulations", "region": "KSA",
        "triggers": [
            "sama", "saudi central bank", "financial institution",
            "banking data", "fintech", "payment data",
        ],
        "violations": [
            "unsecured financial data", "no audit trail",
            "unauthorized financial access", "no risk management",
        ],
        "critical_violations": [
            "unsecured financial data", "unauthorized financial access",
        ],
        "weight": 0.13,
    },

    # ══════════════════════════════════════════════════════════════════════
    # MIDDLE EAST — Qatar, Bahrain, Kuwait, Oman, GCC
    # ══════════════════════════════════════════════════════════════════════
    "qatar_pdp": {
        "name": "Qatar PDP Law", "region": "Qatar",
        "triggers": [
            "personal data", "qatari residents", "data controller",
            "pdp law", "data subject",
        ],
        "violations": [
            "no consent", "unauthorized data transfer",
            "no data protection measures", "data sold to third parties",
        ],
        "critical_violations": ["data sold to third parties"],
        "weight": 0.13,
    },
    "qfc_dp": {
        "name": "QFC DP Regulations", "region": "Qatar",
        "triggers": [
            "qfc", "qatar financial centre", "personal data",
            "data processor", "data subject rights",
        ],
        "violations": [
            "no data subject rights mechanism",
            "unauthorized processing", "no lawful basis",
        ],
        "critical_violations": ["unauthorized processing"],
        "weight": 0.10,
    },
    "qatar_nds": {
        "name": "Qatar NDS", "region": "Qatar",
        "triggers": [
            "national development strategy", "digital transformation",
            "qatar 2030", "government data",
        ],
        "violations": [
            "misuse of government data", "no digital governance",
        ],
        "critical_violations": [],
        "weight": 0.10,
    },
    "bahrain_pdp": {
        "name": "Bahrain PDPL", "region": "Bahrain",
        "triggers": [
            "personal data", "bahrain", "data subject",
            "consent", "data breach notification",
        ],
        "violations": [
            "no consent", "unauthorized cross-border transfer",
            "breach not reported", "no privacy policy",
        ],
        "critical_violations": ["unauthorized cross-border transfer"],
        "weight": 0.12,
    },
    "kuwait_cit": {
        "name": "Kuwait CIT Law", "region": "Kuwait",
        "triggers": [
            "kuwait", "communications and information technology",
            "electronic data", "digital privacy",
        ],
        "violations": [
            "no data security measures",
            "unauthorized electronic surveillance",
        ],
        "critical_violations": ["unauthorized electronic surveillance"],
        "weight": 0.10,
    },
    "oman_ita": {
        "name": "Oman ITA Regulations", "region": "Oman",
        "triggers": [
            "oman", "information technology authority",
            "personal data", "oman digital government",
        ],
        "violations": [
            "no data protection", "unauthorized data processing",
        ],
        "critical_violations": ["unauthorized data processing"],
        "weight": 0.10,
    },
    "gcc_data_governance": {
        "name": "GCC Data Governance", "region": "GCC",
        "triggers": [
            "gcc", "gulf cooperation council", "cross-border data",
            "regional data governance", "gulf states",
        ],
        "violations": [
            "unrestricted cross-border data flow",
            "no regional compliance",
        ],
        "critical_violations": [],
        "weight": 0.08,
    },
}

_ALL_FRAMEWORKS = list(COMPLIANCE_RULES.keys())

# ── Jurisdiction → framework mapping ──────────────────────────────────────
JURISDICTION_MAP: dict[str, list[str]] = {
    "global":   ["iso_42001", "iso_27001", "oecd_ai_principles", "nist_ai_rmf"],
    "eu":       ["gdpr", "eu_ai_act", "iso_42001", "dora"],
    "india":    ["india_dpdp", "india_ai_guidelines_2025", "rbi_free_ai"],
    "usa":      ["us_ccpa_cpra", "us_hipaa", "us_sox", "us_fcra", "colorado_ai_act"],
    "uk":       ["uk_ai_principles", "uk_gdpr"],
    "uae":      ["uae_pdpl", "uae_ai_ethics", "uae_cybersecurity", "difc_dp", "adgm_dp"],
    "ksa":      ["ksa_pdpl", "ksa_ai_ethics", "ksa_cybersecurity", "sama_regulations"],
    "qatar":    ["qatar_pdp", "qfc_dp", "qatar_nds"],
    "bahrain":  ["bahrain_pdp"],
    "kuwait":   ["kuwait_cit"],
    "oman":     ["oman_ita"],
    "gcc":      [
        "gcc_data_governance", "uae_pdpl", "ksa_pdpl", "qatar_pdp",
        "bahrain_pdp", "kuwait_cit", "oman_ita",
    ],
    "apac":     ["singapore_pdpa", "china_pipl", "south_korea_ai_act"],
    "all":      _ALL_FRAMEWORKS,
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class ComplianceResult:
    compliance_score:      float
    frameworks_checked:    list[str] = field(default_factory=list)
    violations_found:      dict = field(default_factory=dict)
    triggers_found:        dict = field(default_factory=dict)
    overall_risk:          str = "LOW"
    evidence_summary:      str = ""
    recommendation:        str = ""
    jurisdictions_covered: list[str] = field(default_factory=list)
    mock_mode:             bool = False


# ---------------------------------------------------------------------------
# Legacy Pydantic models
# ---------------------------------------------------------------------------

class ComplianceControl(BaseModel):
    control_id:  str
    description: str
    status:      str
    framework:   str


class ComplianceResultLegacy(BaseModel):
    controls:            list[ComplianceControl]
    compliant_count:     int
    partial_count:       int
    non_compliant_count: int
    score:               float


_STATUS_WEIGHTS = {
    "compliant": 1.0, "partial": 0.5,
    "non_compliant": 0.0, "not_applicable": None,
}


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def _rule_based_check_compliance(
    text: str,
    frameworks: list[str] | None = None,
    jurisdictions: list[str] | None = None,
) -> ComplianceResult:
    """
    Pure regex/keyword-based compliance checking across 35+ frameworks.
    Used as fallback when Claude is unavailable.

    Scoring:
        critical violation present → 0
        non-critical violation     → 30
        triggers only              → 65
        clean                      → 95
    """
    # ── Resolve framework list ─────────────────────────────────────────
    if frameworks:
        fw_keys = [f.lower().replace("-", "_").replace(" ", "_") for f in frameworks]
    elif jurisdictions:
        fw_keys = []
        for j in jurisdictions:
            fw_keys.extend(JURISDICTION_MAP.get(j.lower(), []))
        fw_keys = list(dict.fromkeys(fw_keys))  # deduplicate
    else:
        fw_keys = _ALL_FRAMEWORKS

    check = [f for f in fw_keys if f in COMPLIANCE_RULES]
    if not check:
        check = list(COMPLIANCE_RULES.keys())[:6]  # sensible fallback

    lower = text.lower()

    violations_found: dict[str, list[str]] = {}
    triggers_found:   dict[str, list[str]] = {}
    weighted_score  = 0.0
    total_weight    = 0.0

    for fw_key in check:
        fw = COMPLIANCE_RULES[fw_key]
        fw_violations   = [v for v in fw["violations"] if v in lower]
        fw_triggers     = [t for t in fw["triggers"]   if t in lower]
        critical_viols  = [v for v in fw.get("critical_violations", []) if v in lower]

        violations_found[fw["name"]] = fw_violations
        triggers_found[fw["name"]]   = fw_triggers

        if critical_viols:
            fw_score = 0.0
        elif fw_violations:
            fw_score = 30.0
        elif fw_triggers:
            fw_score = 65.0
        else:
            fw_score = 95.0

        weighted_score += fw_score * fw["weight"]
        total_weight   += fw["weight"]

    composite = round(weighted_score / total_weight, 2) if total_weight > 0 else 95.0

    # ── Overall risk ──────────────────────────────────────────────────────
    all_violations_flat = [v for vlist in violations_found.values() for v in vlist]
    if all_violations_flat or composite < 40:
        overall_risk = "HIGH"
    elif any(tlist for tlist in triggers_found.values()) or composite < 70:
        overall_risk = "MEDIUM"
    else:
        overall_risk = "LOW"

    # ── Jurisdictions covered ─────────────────────────────────────────────
    regions_set: set[str] = set()
    for fw_key in check:
        regions_set.add(COMPLIANCE_RULES[fw_key]["region"])
    jurisdictions_covered = sorted(regions_set)

    # ── Evidence summary ──────────────────────────────────────────────────
    summary_parts: list[str] = []
    for fw_name, vlist in violations_found.items():
        if vlist:
            summary_parts.append(f"{fw_name}: violations — {', '.join(vlist)}")
        elif triggers_found.get(fw_name):
            summary_parts.append(f"{fw_name}: relevant content detected, review required")
        else:
            summary_parts.append(f"{fw_name}: no issues found")
    evidence_summary = " | ".join(summary_parts) or "All frameworks passed."

    if overall_risk == "HIGH":
        recommendation = (
            "Immediate review required. Potential regulatory violations detected. "
            "Do not use this content without legal/compliance sign-off."
        )
    elif overall_risk == "MEDIUM":
        recommendation = (
            "Compliance-relevant content detected. Ensure proper controls and "
            "documentation are in place before deployment."
        )
    else:
        recommendation = "Content appears compliant with checked frameworks."

    return ComplianceResult(
        compliance_score=composite,
        frameworks_checked=[COMPLIANCE_RULES[f]["name"] for f in check],
        violations_found=violations_found,
        triggers_found=triggers_found,
        overall_risk=overall_risk,
        evidence_summary=evidence_summary,
        recommendation=recommendation,
        jurisdictions_covered=jurisdictions_covered,
        mock_mode=True,
    )


def check_compliance(
    text: str,
    frameworks: list[str] | None = None,
    jurisdictions: list[str] | None = None,
) -> ComplianceResult:
    """
    Evaluate *text* against regulatory frameworks using Claude AI when available,
    falling back to keyword-based detection otherwise.
    """
    print(f"[Compliance] check_compliance() called — AI active: {not _evaluator.mock_mode}")
    # Build context for Claude (framework names + jurisdictions)
    if frameworks:
        fw_names = frameworks
    elif jurisdictions:
        fw_keys: list[str] = []
        for j in jurisdictions:
            fw_keys.extend(JURISDICTION_MAP.get(j.lower(), []))
        fw_names = [COMPLIANCE_RULES[k]["name"] for k in dict.fromkeys(fw_keys) if k in COMPLIANCE_RULES]
    else:
        fw_names = [v["name"] for v in list(COMPLIANCE_RULES.values())[:12]]

    juris_list = jurisdictions or ["global"]

    result = _evaluator.evaluate(
        "compliance",
        text,
        context={"frameworks": fw_names, "jurisdictions": juris_list},
    )

    if result is None:
        return _rule_based_check_compliance(text, frameworks, jurisdictions)

    # Convert Claude EvaluationResult → ComplianceResult
    violations_found: dict[str, list[str]] = {}
    triggers_found:   dict[str, list[str]] = {}
    frameworks_checked: list[str] = []

    for fw_key, fw_data in result.framework_results.items():
        fw_display = fw_data.get("framework_name", fw_key)
        frameworks_checked.append(fw_display)
        violations_found[fw_display] = fw_data.get("violations_found", [])
        triggers_found[fw_display]   = fw_data.get("risk_indicators", [])

    if not frameworks_checked:
        frameworks_checked = fw_names

    overall_risk = result.extra.get("overall_risk", result.severity)
    jurisdictions_covered = result.extra.get("jurisdictions_affected", juris_list)

    return ComplianceResult(
        compliance_score=result.score,
        frameworks_checked=frameworks_checked,
        violations_found=violations_found,
        triggers_found=triggers_found,
        overall_risk=overall_risk,
        evidence_summary=result.reasoning,
        recommendation=result.recommendation,
        jurisdictions_covered=jurisdictions_covered,
        mock_mode=False,
    )


def evaluate_compliance(controls: list[ComplianceControl]) -> ComplianceResultLegacy:
    """Legacy endpoint handler — scores a list of pre-assessed controls."""
    scorable = [c for c in controls if _STATUS_WEIGHTS.get(c.status) is not None]
    if not scorable:
        return ComplianceResultLegacy(
            controls=controls, compliant_count=0, partial_count=0,
            non_compliant_count=0, score=0.0,
        )
    weighted_sum = sum(_STATUS_WEIGHTS[c.status] for c in scorable)  # type: ignore[index]
    score = round((weighted_sum / len(scorable)) * 100, 2)
    return ComplianceResultLegacy(
        controls=controls,
        compliant_count=sum(1 for c in controls if c.status == "compliant"),
        partial_count=sum(1 for c in controls if c.status == "partial"),
        non_compliant_count=sum(1 for c in controls if c.status == "non_compliant"),
        score=score,
    )
