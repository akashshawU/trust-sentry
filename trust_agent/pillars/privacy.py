"""Pillar 2: Privacy — comprehensive PII detection with India, Middle East, and global coverage.

Uses Microsoft Presidio with custom PatternRecognizer objects for:
  • India   — Aadhaar, PAN, Voter ID, GSTIN, UPI, IFSC, mobile
  • UAE     — Emirates ID, mobile (+971)
  • KSA     — National ID (Iqama)
  • Qatar   — QID
  • Global  — SSN, Passport, IBAN, Credit Card, Email, Phone, IP, Person, Location

Redaction rules (smart filtering applied before anonymization):
  • NEVER redact: DATE_TIME, LOCATION, NRP, URL, ORGANIZATION
  • ALWAYS redact: IN_AADHAAR, IN_PAN, UAE_EMIRATES_ID, KSA_NATIONAL_ID,
                   US_SSN, CREDIT_CARD, IBAN_CODE, PASSPORT, MEDICAL_LICENSE
  • PERSON: skip if preceded by salutation (Dear/Mr./Ms./Dr./To:/CC:/From:)
  • EMAIL_ADDRESS: redact personal domains (gmail/yahoo/hotmail); keep work domains
"""

import re

from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
)
from presidio_anonymizer import AnonymizerEngine
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# PII severity and penalty catalogue
# ---------------------------------------------------------------------------

PII_SEVERITY_MAP: dict[str, dict] = {
    # ── Critical identity documents (penalty 30) ──────────────────────────
    "IN_AADHAAR":         {"penalty": 30, "region": "India",       "severity": "critical"},
    "US_SSN":             {"penalty": 30, "region": "Global",      "severity": "critical"},
    "UAE_EMIRATES_ID":    {"penalty": 30, "region": "Middle East", "severity": "critical"},
    "KSA_NATIONAL_ID":    {"penalty": 28, "region": "Middle East", "severity": "critical"},
    # ── National identity documents (penalty 25) ──────────────────────────
    "IN_PAN":             {"penalty": 25, "region": "India",       "severity": "high"},
    "PASSPORT":           {"penalty": 25, "region": "Global",      "severity": "high"},
    "IN_PASSPORT":        {"penalty": 25, "region": "India",       "severity": "high"},
    "UAE_PASSPORT":       {"penalty": 25, "region": "Middle East", "severity": "high"},
    "KSA_PASSPORT":       {"penalty": 25, "region": "Middle East", "severity": "high"},
    "QATAR_QID":          {"penalty": 25, "region": "Middle East", "severity": "high"},
    "IN_VOTER_ID":        {"penalty": 22, "region": "India",       "severity": "high"},
    "IN_DRIVING_LICENCE": {"penalty": 20, "region": "India",       "severity": "high"},
    "IN_GSTIN":           {"penalty": 20, "region": "India",       "severity": "medium"},
    # ── Financial identifiers (penalty 25) ────────────────────────────────
    "CREDIT_CARD":        {"penalty": 25, "region": "Global",      "severity": "high"},
    "IN_BANK_ACCOUNT":    {"penalty": 25, "region": "India",       "severity": "high"},
    "IBAN_CODE":          {"penalty": 25, "region": "Global",      "severity": "high"},
    "IN_IFSC":            {"penalty": 18, "region": "India",       "severity": "medium"},
    "IN_UPI_ID":          {"penalty": 20, "region": "India",       "severity": "high"},
    # ── Medical (penalty 22) ──────────────────────────────────────────────
    "MEDICAL_LICENSE":    {"penalty": 22, "region": "Global",      "severity": "high"},
    "US_ITIN":            {"penalty": 22, "region": "Global",      "severity": "high"},
    # ── Contact details (penalty 15) ─────────────────────────────────────
    "EMAIL_ADDRESS":      {"penalty": 15, "region": "Global",      "severity": "medium"},
    "PHONE_NUMBER":       {"penalty": 15, "region": "Global",      "severity": "medium"},
    "IN_MOBILE":          {"penalty": 15, "region": "India",       "severity": "medium"},
    "UAE_MOBILE":         {"penalty": 15, "region": "Middle East", "severity": "medium"},
    # ── Personal identifiers (lower penalty) ─────────────────────────────
    "PERSON":             {"penalty": 10, "region": "Global",      "severity": "low"},
    "NRP":                {"penalty": 10, "region": "Global",      "severity": "low"},
    "IP_ADDRESS":         {"penalty": 10, "region": "Global",      "severity": "medium"},
    # ── Low-risk context entities ──────────────────────────────────────────
    "LOCATION":           {"penalty": 5,  "region": "Global",      "severity": "low"},
    "URL":                {"penalty": 5,  "region": "Global",      "severity": "low"},
    "DATE_TIME":          {"penalty": 3,  "region": "Global",      "severity": "low"},
}

_CRITICAL_TYPES = {
    k for k, v in PII_SEVERITY_MAP.items() if v["severity"] == "critical"
}

# ---------------------------------------------------------------------------
# Smart redaction filter rules
# ---------------------------------------------------------------------------

# Entity types that should NEVER be redacted (too broad / cause false positives)
_NEVER_REDACT_TYPES: set[str] = {
    "DATE_TIME", "LOCATION", "NRP", "URL", "ORGANIZATION",
}

# Entity types that are ALWAYS redacted regardless of context
_ALWAYS_REDACT_TYPES: set[str] = {
    "IN_AADHAAR", "IN_PAN", "UAE_EMIRATES_ID", "KSA_NATIONAL_ID",
    "US_SSN", "CREDIT_CARD", "IBAN_CODE", "PASSPORT",
    "IN_PASSPORT", "UAE_PASSPORT", "KSA_PASSPORT", "MEDICAL_LICENSE",
}

# Personal email domains — these are redacted; work/corporate domains are kept
_PERSONAL_EMAIL_DOMAINS: set[str] = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "yahoo.co.uk",
    "hotmail.com", "hotmail.co.in", "outlook.com", "outlook.in",
    "icloud.com", "protonmail.com", "rediffmail.com", "live.com",
}

# Salutation/header keywords that precede person names in professional contexts
_SALUTATION_PREFIXES = re.compile(
    r"\b(?:dear|mr|mrs|ms|miss|dr|prof|sir|madam|to|cc|from|attn|hi|hello)\b\.?\s*$",
    re.IGNORECASE,
)


def _is_professional_context_person(text: str, start: int, window: int = 45) -> bool:
    """Return True if the entity at `start` is preceded by a professional salutation.

    Checks up to `window` characters before the entity start for patterns like
    'Dear Mr.', 'To:', 'From:', 'CC:', 'Hi', 'Hello' etc.
    """
    prefix = text[max(0, start - window): start].strip()
    # Check last word/phrase of prefix against salutation list
    return bool(_SALUTATION_PREFIXES.search(prefix))


def _is_personal_email(text: str, start: int, end: int) -> bool:
    """Return True if the email address belongs to a personal (non-work) domain."""
    raw = text[start:end].lower().strip()
    if "@" not in raw:
        return False
    domain = raw.split("@", 1)[-1].split(">")[0].rstrip(".").strip()
    return domain in _PERSONAL_EMAIL_DOMAINS


def _should_redact(entity_type: str, text: str, start: int, end: int) -> bool:
    """Decide whether a Presidio entity should be included in redaction."""
    if entity_type in _ALWAYS_REDACT_TYPES:
        return True
    if entity_type in _NEVER_REDACT_TYPES:
        return False
    if entity_type == "PERSON":
        # Skip names that appear right after salutations (e.g. "Dear Mr. Iyer")
        return not _is_professional_context_person(text, start)
    if entity_type == "EMAIL_ADDRESS":
        # Only redact personal/consumer email addresses
        return _is_personal_email(text, start, end)
    return True  # default: redact

# ---------------------------------------------------------------------------
# Custom PatternRecognizer objects — India and Middle East PII
# ---------------------------------------------------------------------------

# India — Aadhaar: 12 digits in groups of 4 separated by space or dash
AADHAAR_PATTERN = PatternRecognizer(
    supported_entity="IN_AADHAAR",
    patterns=[
        Pattern("aadhaar_spaced_or_dashed", r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}\b", 0.9),
        Pattern("aadhaar_plain_12digit",    r"\b[2-9]\d{11}\b",                   0.75),
    ],
    context=["aadhaar", "uid", "aadhar", "uidai", "unique identification"],
)

# India — PAN: 5 uppercase letters + 4 digits + 1 uppercase letter
PAN_PATTERN = PatternRecognizer(
    supported_entity="IN_PAN",
    patterns=[
        Pattern("pan_pattern", r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", 0.85),
    ],
    context=["pan", "permanent account", "income tax", "pan card"],
)

# India — Voter ID (EPIC): 3 uppercase letters + 7 digits
VOTER_ID_PATTERN = PatternRecognizer(
    supported_entity="IN_VOTER_ID",
    patterns=[
        Pattern("voter_id_pattern", r"\b[A-Z]{3}[0-9]{7}\b", 0.75),
    ],
    context=["voter", "election", "voter id", "epic"],
)

# UAE — Emirates ID: 784-XXXX-XXXXXXX-X
EMIRATES_ID_PATTERN = PatternRecognizer(
    supported_entity="UAE_EMIRATES_ID",
    patterns=[
        Pattern("emirates_id_dashed", r"\b784-[0-9]{4}-[0-9]{7}-[0-9]{1}\b", 0.95),
        Pattern("emirates_id_plain",  r"\b784[0-9]{12}\b",                     0.85),
    ],
    context=["emirates id", "eid", "emirates", "uae id"],
)

# KSA — National ID (Iqama): 10 digits starting with 1 or 2
KSA_NID_PATTERN = PatternRecognizer(
    supported_entity="KSA_NATIONAL_ID",
    patterns=[
        Pattern("ksa_nid_pattern", r"\b[12][0-9]{9}\b", 0.75),
    ],
    context=["iqama", "national id", "saudi id", "absher"],
)

# India — Mobile: +91 prefix or 10-digit starting with 6-9
INDIA_MOBILE_PATTERN = PatternRecognizer(
    supported_entity="IN_MOBILE",
    patterns=[
        Pattern("india_mobile_with_code", r"\+91[\s\-]?[6-9][0-9]{9}\b", 0.9),
        Pattern("india_mobile_local",     r"\b[6-9][0-9]{9}\b",           0.7),
    ],
    context=["mobile", "phone", "contact", "whatsapp", "call"],
)

# India — IFSC: 4 uppercase letters + 0 + 6 alphanumeric characters
IFSC_PATTERN = PatternRecognizer(
    supported_entity="IN_IFSC",
    patterns=[
        Pattern("ifsc_pattern", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.85),
    ],
    context=["ifsc", "bank", "transfer", "neft", "rtgs", "imps"],
)

# India — GSTIN: 2 digits + 5 letters + 4 digits + 3 alphanumeric
GSTIN_PATTERN = PatternRecognizer(
    supported_entity="IN_GSTIN",
    patterns=[
        Pattern("gstin_pattern",
                r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b", 0.9),
    ],
    context=["gstin", "gst", "goods and service"],
)

# Qatar — QID: 11-digit number (context required to reduce false positives)
QATAR_QID_PATTERN = PatternRecognizer(
    supported_entity="QATAR_QID",
    patterns=[
        Pattern("qatar_qid_pattern", r"\b\d{11}\b", 0.7),
    ],
    context=["qid", "qatar id", "residence permit"],
)

# UAE — Mobile: +971 followed by 9 digits
UAE_MOBILE_PATTERN = PatternRecognizer(
    supported_entity="UAE_MOBILE",
    patterns=[
        Pattern("uae_mobile_pattern", r"\+971[\s\-]?\d{9}\b", 0.85),
    ],
    context=["uae mobile", "dubai number", "+971"],
)

# ---------------------------------------------------------------------------
# Build Presidio AnalyzerEngine with full custom registry
# ---------------------------------------------------------------------------

_registry = RecognizerRegistry()
_registry.load_predefined_recognizers()
for _recognizer in [
    AADHAAR_PATTERN,
    PAN_PATTERN,
    VOTER_ID_PATTERN,
    EMIRATES_ID_PATTERN,
    KSA_NID_PATTERN,
    INDIA_MOBILE_PATTERN,
    IFSC_PATTERN,
    GSTIN_PATTERN,
    QATAR_QID_PATTERN,
    UAE_MOBILE_PATTERN,
]:
    _registry.add_recognizer(_recognizer)

_analyzer   = AnalyzerEngine(registry=_registry)
_anonymizer = AnonymizerEngine()

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

class PrivacyAnalysisResult(BaseModel):
    original_text:     str
    anonymized_text:   str
    entities_found:    list[dict]
    risk_score:        float            # 0-100 — higher = more PII exposure
    privacy_score:     float = 100.0   # 100 - risk_score (convenience; higher = safer)
    entity_count:      int   = 0
    critical_entities: list[str] = []
    recommendation:    str   = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_and_anonymize(text: str, language: str = "en") -> PrivacyAnalysisResult:
    """
    Detect PII using Presidio (with custom PatternRecognizers for India & Middle East).

    Scoring uses severity-weighted penalties from PII_SEVERITY_MAP so that low-risk
    entities (LOCATION, DATE_TIME) do not unfairly penalise legitimate requests.

    Returns :class:`PrivacyAnalysisResult` with:
      • ``privacy_score``  0-100 (100 = no PII detected / fully safe)
      • ``risk_score``     0-100 (100 = maximum PII exposure)
      • ``entities_found`` enriched list with entity_type, span, severity, region
    """
    if not text or not text.strip():
        return PrivacyAnalysisResult(
            original_text=text or "",
            anonymized_text=text or "",
            entities_found=[],
            risk_score=0.0,
            privacy_score=100.0,
            entity_count=0,
            critical_entities=[],
            recommendation="No PII detected. Text appears safe for processing.",
        )

    # ── Presidio detection ───────────────────────────────────────────────────
    results = _analyzer.analyze(text=text, language=language)

    # ── Smart redaction filter — apply context-aware rules ───────────────────
    # Only pass entities that should genuinely be anonymized to the anonymizer.
    # This prevents false positives like "Dear Mr. Iyer" or legitimate org names.
    redact_results = [
        r for r in results
        if _should_redact(r.entity_type, text, r.start, r.end)
    ]
    anonymized = _anonymizer.anonymize(text=text, analyzer_results=redact_results)

    # ── Enrich each result with severity metadata ────────────────────────────
    enriched_entities: list[dict] = []
    risk_score = 0.0
    critical_entities: list[str] = []

    for r in results:
        etype = r.entity_type
        meta  = PII_SEVERITY_MAP.get(
            etype, {"penalty": 10, "region": "Global", "severity": "low"}
        )
        risk_score += meta["penalty"]
        enriched_entities.append({
            "entity_type":  etype,
            "start":        r.start,
            "end":          r.end,
            "score":        round(r.score, 3),
            "matched_text": text[r.start:r.end],
            "severity":     meta["severity"],
            "region":       meta["region"],
        })
        if etype in _CRITICAL_TYPES:
            critical_entities.append(etype)

    risk_score    = round(min(100.0, risk_score), 2)
    privacy_score = round(max(0.0, 100.0 - risk_score), 2)
    entity_count  = len(enriched_entities)

    # ── Recommendation ────────────────────────────────────────────────────────
    if entity_count == 0:
        recommendation = "No PII detected. Text appears safe for processing."
    elif critical_entities:
        recommendation = (
            f"CRITICAL PII detected: {', '.join(sorted(set(critical_entities)))}. "
            "Immediately anonymize or encrypt before any processing. "
            "Review against applicable data protection laws (DPDP, GDPR, UAE PDPL)."
        )
    elif privacy_score < 50:
        recommendation = (
            "Significant PII exposure detected. Redact all sensitive entities "
            "before using in AI systems or sharing externally."
        )
    else:
        types = list({e["entity_type"] for e in enriched_entities})
        recommendation = (
            f"PII detected ({', '.join(types[:5])}). "
            "Review the anonymized version before processing or sharing."
        )

    return PrivacyAnalysisResult(
        original_text=text,
        anonymized_text=anonymized.text,
        entities_found=enriched_entities,
        risk_score=risk_score,
        privacy_score=privacy_score,
        entity_count=entity_count,
        critical_entities=sorted(set(critical_entities)),
        recommendation=recommendation,
    )


def privacy_pillar_score(text: str) -> float:
    """Return a 0-100 privacy score (higher = better privacy posture)."""
    return analyze_and_anonymize(text).privacy_score
