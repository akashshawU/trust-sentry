"""Pillar 3: Access Control — enterprise RBAC with 30+ roles, resource sensitivity, and action risk."""

import re
from dataclasses import dataclass, field
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Role Registry — 30+ enterprise roles with permissions, risk level, trust boost
# ---------------------------------------------------------------------------

ROLE_REGISTRY: dict[str, dict] = {
    # ── C-Suite ──────────────────────────────────────────────────────────────
    "ceo": {
        "permissions": ["read", "write", "export", "configure", "audit", "approve", "override"],
        "risk_level": "low", "trust_boost": 15, "seniority": "executive",
    },
    "cfo": {
        "permissions": ["read", "write", "export", "configure", "audit", "approve"],
        "risk_level": "low", "trust_boost": 14, "seniority": "executive",
    },
    "cto": {
        "permissions": ["read", "write", "export", "configure", "audit", "approve", "execute"],
        "risk_level": "low", "trust_boost": 14, "seniority": "executive",
    },
    "coo": {
        "permissions": ["read", "write", "export", "configure", "audit", "approve"],
        "risk_level": "low", "trust_boost": 13, "seniority": "executive",
    },
    # ── Partnership / Director ────────────────────────────────────────────────
    "partner": {
        "permissions": ["read", "write", "export", "audit", "approve"],
        "risk_level": "low", "trust_boost": 12, "seniority": "partner",
    },
    "director": {
        "permissions": ["read", "write", "export", "audit", "approve"],
        "risk_level": "low", "trust_boost": 11, "seniority": "director",
    },
    # ── Senior Manager (generic) ──────────────────────────────────────────────
    "senior_manager": {
        "permissions": ["read", "write", "export", "audit"],
        "risk_level": "low", "trust_boost": 9, "seniority": "senior",
    },
    # ── Generic Manager / Analyst / External ─────────────────────────────────
    "manager": {
        "permissions": ["read", "write", "export"],
        "risk_level": "low", "trust_boost": 7, "seniority": "manager",
    },
    "analyst": {
        "permissions": ["read", "export"],
        "risk_level": "low", "trust_boost": 5, "seniority": "analyst",
    },
    "client": {
        "permissions": [],
        "risk_level": "high", "trust_boost": -15, "seniority": "external",
    },
    "vendor": {
        "permissions": [],
        "risk_level": "high", "trust_boost": -15, "seniority": "external",
    },
    # ── Managers ─────────────────────────────────────────────────────────────
    "finance_manager": {
        "permissions": ["read", "write", "export", "audit"],
        "risk_level": "low", "trust_boost": 10, "seniority": "manager",
    },
    "risk_manager": {
        "permissions": ["read", "write", "export", "audit"],
        "risk_level": "low", "trust_boost": 10, "seniority": "manager",
    },
    "compliance_manager": {
        "permissions": ["read", "write", "export", "audit"],
        "risk_level": "low", "trust_boost": 10, "seniority": "manager",
    },
    "it_manager": {
        "permissions": ["read", "write", "configure", "execute", "audit"],
        "risk_level": "low", "trust_boost": 10, "seniority": "manager",
    },
    "hr_manager": {
        "permissions": ["read", "write", "export"],
        "risk_level": "medium", "trust_boost": 8, "seniority": "manager",
    },
    "operations_manager": {
        "permissions": ["read", "write", "export"],
        "risk_level": "low", "trust_boost": 9, "seniority": "manager",
    },
    # ── Senior / Lead Analysts ────────────────────────────────────────────────
    "senior_analyst": {
        "permissions": ["read", "write", "export"],
        "risk_level": "low", "trust_boost": 8, "seniority": "senior",
    },
    "lead_analyst": {
        "permissions": ["read", "write", "export"],
        "risk_level": "low", "trust_boost": 8, "seniority": "senior",
    },
    "financial_analyst": {
        "permissions": ["read", "export"],
        "risk_level": "low", "trust_boost": 7, "seniority": "analyst",
    },
    "risk_analyst": {
        "permissions": ["read", "export"],
        "risk_level": "low", "trust_boost": 7, "seniority": "analyst",
    },
    "data_analyst": {
        "permissions": ["read", "export"],
        "risk_level": "low", "trust_boost": 6, "seniority": "analyst",
    },
    "compliance_analyst": {
        "permissions": ["read", "audit", "export"],
        "risk_level": "low", "trust_boost": 7, "seniority": "analyst",
    },
    # ── Consultants ───────────────────────────────────────────────────────────
    "senior_consultant": {
        "permissions": ["read", "export"],
        "risk_level": "medium", "trust_boost": 5, "seniority": "senior",
    },
    "consultant": {
        "permissions": ["read", "export"],
        "risk_level": "medium", "trust_boost": 3, "seniority": "mid",
    },
    "junior_consultant": {
        "permissions": ["read"],
        "risk_level": "medium", "trust_boost": 1, "seniority": "junior",
    },
    # ── Associates ────────────────────────────────────────────────────────────
    "associate": {
        "permissions": ["read"],
        "risk_level": "medium", "trust_boost": 0, "seniority": "junior",
    },
    "intern": {
        "permissions": ["read"],
        "risk_level": "high", "trust_boost": -10, "seniority": "intern",
    },
    # ── Technical Roles ────────────────────────────────────────────────────────
    "developer": {
        "permissions": ["read", "write", "execute", "configure"],
        "risk_level": "medium", "trust_boost": 5, "seniority": "technical",
    },
    "senior_developer": {
        "permissions": ["read", "write", "execute", "configure", "audit"],
        "risk_level": "low", "trust_boost": 8, "seniority": "technical",
    },
    "data_engineer": {
        "permissions": ["read", "write", "execute"],
        "risk_level": "medium", "trust_boost": 5, "seniority": "technical",
    },
    # ── Admin / Audit ─────────────────────────────────────────────────────────
    "admin": {
        "permissions": ["read", "write", "delete", "export", "configure", "audit", "execute"],
        "risk_level": "low", "trust_boost": 12, "seniority": "admin",
    },
    "system_admin": {
        "permissions": ["read", "write", "delete", "export", "configure", "audit", "execute", "override"],
        "risk_level": "low", "trust_boost": 13, "seniority": "admin",
    },
    "auditor": {
        "permissions": ["read", "audit"],
        "risk_level": "low", "trust_boost": 10, "seniority": "specialist",
    },
    "external_auditor": {
        "permissions": ["read"],
        "risk_level": "medium", "trust_boost": 2, "seniority": "external",
    },
    # ── External / Limited ────────────────────────────────────────────────────
    "user": {
        "permissions": ["read"],
        "risk_level": "medium", "trust_boost": 0, "seniority": "standard",
    },
    "guest": {
        "permissions": [],
        "risk_level": "high", "trust_boost": -20, "seniority": "guest",
    },
    "external_user": {
        "permissions": [],
        "risk_level": "high", "trust_boost": -25, "seniority": "external",
    },
    "unknown": {
        "permissions": [],
        "risk_level": "critical", "trust_boost": -50, "seniority": "unknown",
    },
}

# ---------------------------------------------------------------------------
# Resource Sensitivity Map
# ---------------------------------------------------------------------------

RESOURCE_SENSITIVITY_MAP: dict[str, dict] = {
    # critical — maximum penalty for unauthorized access
    "financial-data":     {"level": "critical", "penalty": 35},
    "financial_data":     {"level": "critical", "penalty": 35},
    "client-records":     {"level": "critical", "penalty": 35},
    "client_records":     {"level": "critical", "penalty": 35},
    "audit-logs":         {"level": "critical", "penalty": 30},
    "audit_logs":         {"level": "critical", "penalty": 30},
    "api-keys":           {"level": "critical", "penalty": 40},
    "api_keys":           {"level": "critical", "penalty": 40},
    "user-database":      {"level": "critical", "penalty": 35},
    "user_database":      {"level": "critical", "penalty": 35},
    "pii":                {"level": "critical", "penalty": 40},
    "credentials":        {"level": "critical", "penalty": 40},
    # high — significant penalty
    "system-config":      {"level": "high", "penalty": 25},
    "system_config":      {"level": "high", "penalty": 25},
    "confidential":       {"level": "high", "penalty": 25},
    "restricted":         {"level": "high", "penalty": 25},
    "classified":         {"level": "high", "penalty": 30},
    "salary-data":        {"level": "high", "penalty": 28},
    "salary_data":        {"level": "high", "penalty": 28},
    "strategic-plans":    {"level": "high", "penalty": 25},
    "strategic_plans":    {"level": "high", "penalty": 25},
    # medium
    "reports":            {"level": "medium", "penalty": 10},
    "dashboards":         {"level": "medium", "penalty": 10},
    "model-outputs":      {"level": "medium", "penalty": 10},
    "model_outputs":      {"level": "medium", "penalty": 10},
    "trust-scores":       {"level": "medium", "penalty": 10},
    "trust_scores":       {"level": "medium", "penalty": 10},
    # low — minimal concern
    "public-docs":        {"level": "low", "penalty": 0},
    "public_docs":        {"level": "low", "penalty": 0},
    "knowledge-base":     {"level": "low", "penalty": 0},
    "knowledge_base":     {"level": "low", "penalty": 0},
}

# ---------------------------------------------------------------------------
# Action Risk Map
# ---------------------------------------------------------------------------

ACTION_RISK_MAP: dict[str, dict] = {
    "read":     {"risk": "low",      "penalty": 0},
    "export":   {"risk": "medium",   "penalty": 8},
    "write":    {"risk": "medium",   "penalty": 10},
    "execute":  {"risk": "medium",   "penalty": 12},
    "delete":   {"risk": "high",     "penalty": 20},
    "configure":{"risk": "high",     "penalty": 18},
    "audit":    {"risk": "low",      "penalty": 0},
    "approve":  {"risk": "medium",   "penalty": 8},
    "override": {"risk": "critical", "penalty": 35},
}


# ---------------------------------------------------------------------------
# Foundation 1 — Universal Role Detection
# ---------------------------------------------------------------------------

def normalise_caller_id(caller_id: str) -> str:
    """
    Convert a raw caller_id into a clean, space-separated string for matching.
    Handles underscores, hyphens, trailing numbers, location prefixes, etc.
    """
    text = caller_id.lower().strip()
    # Replace separators with space
    text = re.sub(r'[-_.]', ' ', text)
    # Remove trailing numbers (e.g. "auditor 001" → "auditor")
    text = re.sub(r'\s+\d+\s*$', '', text).strip()
    # Remove leading numbers
    text = re.sub(r'^\d+\s+', '', text).strip()
    # Remove common location / org prefixes that should not affect role matching
    _DEPT_PREFIXES = [
        'mumbai', 'delhi', 'dubai', 'riyadh', 'london', 'india',
        'uae', 'ksa', 'gcc', 'apac', 'north', 'south', 'east', 'west',
        'regional', 'global', 'group', 'head', 'office', 'team',
    ]
    for prefix in _DEPT_PREFIXES:
        text = text.replace(prefix + ' ', '').strip()
    return text


# Role synonym map — ordered (highest privilege first) for deterministic matching.
# Synonyms are checked as substrings against the normalised caller_id.
ROLE_SYNONYMS: dict[str, list[str]] = {
    "ceo": [
        "ceo", "chief executive", "chief exec", "managing director",
        "md", "president", "group ceo",
    ],
    "cfo": [
        "cfo", "chief financial", "chief finance", "finance director",
        "financial director", "fd", "group cfo", "vp finance",
        "head of finance",
    ],
    "cto": [
        "cto", "chief technology", "chief technical", "tech director",
        "technology director", "vp tech", "vp engineering",
        "head of tech", "head of engineering",
    ],
    "partner": [
        "partner", "managing partner", "senior partner", "equity partner",
        "engagement partner", "service partner",
    ],
    "director": [
        "director", "associate director", "executive director", "group director",
        "hr director", "finance director", "it director", "compliance director",
        "risk director", "audit director", "legal director", "ops director",
    ],
    "senior_manager": [
        "senior manager", "sr manager", "snr manager", "seniormanager",
    ],
    "finance_manager": [
        "finance manager", "financial manager", "finance mgr",
        "accounts manager", "fp&a manager", "treasury manager",
        "controller", "financial controller", "head of accounts",
    ],
    "hr_manager": [
        "hr manager", "human resources manager", "people manager", "hr mgr",
        "head of hr", "head of people", "people operations", "hrbp",
        "hr business partner",
    ],
    "it_manager": [
        "it manager", "infrastructure manager", "systems manager", "it mgr",
        "head of it", "it lead", "technology manager",
    ],
    "compliance_manager": [
        "compliance manager", "compliance mgr", "head of compliance",
        "regulatory manager", "compliance officer", "chief compliance",
    ],
    "risk_manager": [
        "risk manager", "risk mgr", "head of risk", "risk officer",
        "chief risk", "cro",
    ],
    "manager": [
        "manager", "mgr", "team lead", "team leader", "section head",
        "unit head", "group manager", "line manager", "account manager",
    ],
    "auditor": [
        "auditor", "audit", "internal auditor", "senior auditor",
        "lead auditor", "audit manager", "audit lead", "audit associate",
        "it auditor", "financial auditor", "sox auditor", "itgc auditor",
        "external auditor", "audit supervisor", "audit senior",
    ],
    "senior_analyst": [
        "senior analyst", "sr analyst", "snr analyst", "lead analyst",
        "principal analyst", "staff analyst", "specialist analyst",
        "analyst ii", "analyst iii", "analyst senior",
    ],
    "analyst": [
        "analyst", "associate analyst", "junior analyst", "analyst i",
        "research analyst", "data analyst", "business analyst", "ba ",
        "financial analyst", "risk analyst",
    ],
    "senior_consultant": [
        "senior consultant", "sr consultant", "principal consultant",
        "lead consultant", "consultant ii", "consultant iii",
        "managing consultant",
    ],
    "consultant": [
        "consultant", "associate consultant", "junior consultant",
        "advisor", "adviser", "specialist", "associate",
    ],
    "developer": [
        "developer", "dev ", "engineer", "software engineer", "swe",
        "programmer", "coder", "architect", "devops", "sre",
        "data engineer", "ml engineer", "ai engineer",
    ],
    "admin": [
        "admin", "administrator", "system admin", "sysadmin",
        "it admin", "network admin", "database admin", "dba",
        "super user", "superuser", "root user",
    ],
    "intern": [
        "intern", "trainee", "apprentice", "graduate trainee", "fresher",
        "probationer", "placement student", "summer intern", "winter intern",
    ],
    "client": [
        "client", "customer", "external client", "client user",
        "guest client", "client access",
    ],
    "vendor": [
        "vendor", "supplier", "contractor", "third party", "third-party",
        "external contractor", "outsource",
    ],
    "guest": [
        "guest", "visitor", "temporary", "temp user", "demo user",
        "trial user", "readonly",
    ],
    "unknown": [
        "unknown", "anonymous", "anon", "unidentified", "undefined",
        "null", "none", "n/a", "test",
    ],
}

# Detection order: highest privilege first — first match wins.
# CRITICAL: "director" MUST precede "cto" because "cto" is a literal
# substring of "dire-cto-r". Checking director first prevents the trap.
_ROLE_DETECTION_ORDER: list[str] = [
    "ceo", "cfo", "partner", "director", "cto",   # director before cto
    "senior_manager",
    "finance_manager", "hr_manager", "it_manager",
    "compliance_manager", "risk_manager",
    "manager",
    "auditor",
    "senior_analyst", "analyst",
    "senior_consultant", "consultant",
    "developer", "admin",
    "intern", "client", "vendor", "guest", "unknown",
]

# Professional-context fallback — if none of the above match but a seniority
# indicator is present, default to analyst-level rather than unknown.
_PROFESSIONAL_INDICATORS: list[str] = [
    "officer", "head ", "chief ", "vp ", "vice president",
    "lead ", "principal", "staff ", "associate",
]


def detect_role(caller_id: str) -> str:
    """
    Infer caller role from a caller_id string.

    Algorithm:
    1. Normalise (separators → spaces, strip trailing digits/location prefixes)
    2. Check if normalised text is itself a role key in ROLE_REGISTRY
    3. Match ROLE_SYNONYMS from highest privilege to lowest (first match wins)
    4. Fallback to 'analyst' if any professional indicator is present
    5. Return 'unknown' if nothing matches
    """
    normalised = normalise_caller_id(caller_id)

    # Exact role-key match after normalisation
    if normalised in ROLE_REGISTRY:
        return normalised

    # Synonym matching — highest privilege first
    for role in _ROLE_DETECTION_ORDER:
        for synonym in ROLE_SYNONYMS.get(role, []):
            if synonym in normalised:
                return role

    # Professional-context fallback
    for indicator in _PROFESSIONAL_INDICATORS:
        if indicator in normalised:
            return "analyst"

    return "unknown"


# ---------------------------------------------------------------------------
# Resource sensitivity lookup
# ---------------------------------------------------------------------------

def _get_resource_sensitivity(resource: str) -> tuple[str, int]:
    """Return (level, penalty) for the given resource name."""
    res_lower = resource.lower().replace("-", "_")
    # Exact match first
    if res_lower in RESOURCE_SENSITIVITY_MAP:
        d = RESOURCE_SENSITIVITY_MAP[res_lower]
        return d["level"], d["penalty"]
    # Substring match
    for key, d in RESOURCE_SENSITIVITY_MAP.items():
        if key in res_lower or res_lower in key:
            return d["level"], d["penalty"]
    return "standard", 0


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class AccessResult:
    access_score:         float
    role_detected:        str
    role_key:             str
    action_permitted:     bool
    resource_sensitivity: str           # critical / high / medium / standard / low
    risk_flags:           list[str] = field(default_factory=list)
    recommendation:       str = ""
    trust_level:          str = ""      # HIGH / MEDIUM / LOW / BLOCKED


# ---------------------------------------------------------------------------
# Legacy Pydantic models kept for backward compatibility with existing endpoints
# ---------------------------------------------------------------------------

class AccessRequest(BaseModel):
    user_id:  str
    role:     str
    resource: str
    action:   str


class AccessDecision(BaseModel):
    allowed: bool
    reason:  str
    score:   float


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def check_access(caller_id: str, resource: str, action: str) -> AccessResult:
    """
    Evaluate whether *caller_id* may perform *action* on *resource*.

    Role is inferred from caller_id via :func:`detect_role`.
    Returns an :class:`AccessResult` with 0-100 access score.
    """
    role_key = detect_role(caller_id)
    # Safe fallback: if detect_role returns a key not in ROLE_REGISTRY, map to nearest
    _ROLE_FALLBACK: dict[str, str] = {
        "senior_manager": "operations_manager",
        "manager":        "operations_manager",
        "analyst":        "financial_analyst",
        "client":         "external_user",
        "vendor":         "external_user",
        "ciso":           "cto",
    }
    if role_key not in ROLE_REGISTRY:
        role_key = _ROLE_FALLBACK.get(role_key, "unknown")
    policy   = ROLE_REGISTRY[role_key]

    action_lc    = action.lower()
    action_info  = ACTION_RISK_MAP.get(action_lc, {"risk": "medium", "penalty": 10})
    perm_granted = action_lc in policy["permissions"]

    res_level, res_penalty = _get_resource_sensitivity(resource)
    is_sensitive = res_level in ("critical", "high")

    score       = 100.0
    risk_flags: list[str] = []

    # ── Unknown identity is immediately capped ────────────────────────────
    if role_key == "unknown":
        score = 10.0
        risk_flags.append("Caller identity could not be verified — defaulting to BLOCKED")
        return AccessResult(
            access_score=score,
            role_detected=role_key,
            role_key=role_key,
            action_permitted=False,
            resource_sensitivity=res_level,
            risk_flags=risk_flags,
            recommendation="Block: unverified caller identity. Require authentication before any access.",
            trust_level="BLOCKED",
        )

    # ── Action not in role permissions ────────────────────────────────────
    if not perm_granted:
        score -= 50
        risk_flags.append(f"Action '{action_lc}' not permitted for role '{role_key}'")

    # ── Sensitive / critical resource penalty ─────────────────────────────
    if is_sensitive:
        # Only apply penalty if role seniority is too low
        low_seniority_roles = {"intern", "guest", "external_user", "user", "associate", "junior_consultant"}
        if role_key in low_seniority_roles:
            score -= res_penalty
            risk_flags.append(
                f"Sensitive resource '{resource}' ({res_level}) accessed by low-seniority role '{role_key}'"
            )
        elif res_level == "critical" and policy["seniority"] in ("junior", "intern", "guest", "external"):
            score -= res_penalty
            risk_flags.append(f"Critical resource '{resource}' requires elevated role")

    # ── Cross-domain check: non-finance roles accessing financial data ────
    finance_resources = {"financial-data", "financial_data", "salary-data", "salary_data"}
    finance_roles     = {
        "ceo", "cfo", "finance_manager", "financial_analyst", "risk_analyst",
        "auditor", "external_auditor", "admin", "system_admin", "partner", "director",
        "compliance_manager", "compliance_analyst", "senior_analyst", "lead_analyst",
    }
    res_lower = resource.lower().replace("-", "_")
    if any(fr in res_lower for fr in {"financial", "salary", "payroll"}):
        if role_key not in finance_roles:
            score -= 20
            risk_flags.append(
                f"Cross-domain access: role '{role_key}' is not authorised for financial resources"
            )

    # ── High-risk action penalty ──────────────────────────────────────────
    if action_info["risk"] in ("high", "critical") and not perm_granted:
        score -= action_info["penalty"]
        risk_flags.append(
            f"High-risk action '{action_lc}' attempted without permission (risk: {action_info['risk']})"
        )

    # ── Trust boost from role ─────────────────────────────────────────────
    score += policy["trust_boost"]
    score  = max(0.0, min(100.0, round(score, 2)))

    # ── action_permitted: true only if score ≥ 60 and action in permissions
    action_permitted = perm_granted and score >= 60

    # ── Trust level label ─────────────────────────────────────────────────
    if score >= 85:
        trust_level = "HIGH"
    elif score >= 60:
        trust_level = "MEDIUM"
    elif score >= 30:
        trust_level = "LOW"
    else:
        trust_level = "BLOCKED"

    # ── Recommendation ────────────────────────────────────────────────────
    if trust_level == "HIGH":
        recommendation = f"Access granted: role '{role_key}' is well-authorised for this operation."
    elif trust_level == "MEDIUM":
        recommendation = (
            f"Access conditionally permitted: review whether role '{role_key}' "
            f"should have '{action_lc}' access to '{resource}'."
        )
    elif trust_level == "LOW":
        recommendation = (
            f"Access flagged: role '{role_key}' has low trust for this operation. "
            "Require MFA or supervisor approval."
        )
    else:
        recommendation = (
            f"Access blocked: role '{role_key}' must not access '{resource}' "
            f"with action '{action_lc}'. Escalate to security team."
        )

    return AccessResult(
        access_score=score,
        role_detected=role_key,
        role_key=role_key,
        action_permitted=action_permitted,
        resource_sensitivity=res_level,
        risk_flags=risk_flags,
        recommendation=recommendation,
        trust_level=trust_level,
    )


# ---------------------------------------------------------------------------
# Foundation 5 — Resource Synonym Detection
# ---------------------------------------------------------------------------

RESOURCE_SYNONYMS: dict[str, list[str]] = {
    "payroll-data": [
        "payroll", "salary", "salaries", "compensation", "remuneration",
        "pay slip", "payslip", "earnings", "wage", "wages", "pay record",
        "salary band", "salary range", "total compensation", "ctc",
        "cost to company", "pay grade", "incentive", "bonus record",
    ],
    "financial-data": [
        "financial", "finance", "revenue", "profit", "loss", "p&l", "pnl",
        "budget", "forecast", "ebitda", "balance sheet", "income statement",
        "cash flow", "accounts", "ledger", "gl ", "general ledger",
        "financial statement", "financials", "f&a", "financial records",
    ],
    "employee-records": [
        "employee", "staff", "personnel", "hr data", "hr records",
        "people data", "workforce data", "headcount", "employee file",
        "personnel file", "people records",
    ],
    "client-records": [
        "client", "customer", "account", "client data", "customer data",
        "client information", "crm", "client records", "customer records",
        "account data", "engagement data",
    ],
    "audit-logs": [
        "audit", "audit log", "audit trail", "workpaper", "work paper",
        "audit workpaper", "itgc", "sox workpaper", "audit file",
        "control evidence", "audit evidence", "findings", "audit findings",
    ],
    "system-config": [
        "system config", "configuration", "system settings", "settings",
        "api key", "credentials", "password", "secret", "token",
        "access key", "private key", "connection string", "endpoint",
        "infrastructure", "server config",
    ],
    "patient-records": [
        "patient", "medical record", "health record", "diagnosis",
        "prescription", "clinical data", "ehr", "emr", "phi",
        "protected health", "medical history",
    ],
    "contracts": [
        "contract", "agreement", "engagement letter", "sow",
        "statement of work", "nda", "non disclosure", "msa",
        "master service", "addendum", "amendment", "clause", "legal doc",
    ],
}


# ---------------------------------------------------------------------------
# Foundation 2b — Knowledge request keywords (never access sensitive data)
# ---------------------------------------------------------------------------

KNOWLEDGE_KEYWORDS: list[str] = [
    "summary of", "explain", "what is", "overview of", "describe",
    "tell me", "how does", "define", "clause", "article", "section",
    "requirement", "control", "framework", "standard", "policy",
    "guideline", "regulation", "best practice", "iso", "nist",
    "gdpr", "hipaa", "sox", "owasp", "dpdp", "pdpl", "eu ai act",
    "compliance framework", "audit framework", "risk framework",
]


def detect_resource(text: str, ai_resource: str | None = None) -> str:
    """
    Auto-detect the canonical resource type from free-form task description text.

    Priority:
    1. Trust AI-detected resource when it is a valid canonical type
    2. Check for knowledge request signals (→ approved-documents)
    3. Pattern-match RESOURCE_SYNONYMS
    4. Fall back to 'general-data'
    """
    # Priority 1: trust AI result if it is a known canonical type
    _valid_resources = {
        "payroll-data", "financial-data", "employee-records", "client-records",
        "audit-logs", "system-config", "patient-records", "contracts",
        "approved-documents", "general-data",
    }
    if ai_resource and ai_resource in _valid_resources:
        return ai_resource

    text_lower = text.lower()

    # Priority 2: knowledge-request detection (no sensitive data accessed)
    knowledge_count = sum(1 for kw in KNOWLEDGE_KEYWORDS if kw in text_lower)
    if knowledge_count >= 2:
        return "approved-documents"

    # Single strong knowledge signal paired with a standard/framework keyword
    if any(kw in text_lower for kw in ["summary of", "explain", "what is",
                                        "overview of", "how does", "define",
                                        "tell me about"]):
        if any(std in text_lower for std in ["iso", "nist", "gdpr", "hipaa",
                                              "sox", "owasp", "dpdp", "pdpl",
                                              "regulation", "framework",
                                              "standard", "policy", "clause"]):
            return "approved-documents"

    # Priority 3: pattern matching against synonym lists
    for resource, synonyms in RESOURCE_SYNONYMS.items():
        for synonym in synonyms:
            if synonym in text_lower:
                return resource

    return "general-data"


# ---------------------------------------------------------------------------
# Legacy helper kept for backward compatibility with /pillars/access-control
# ---------------------------------------------------------------------------

_LEGACY_POLICY: dict[str, dict[str, list[str]]] = {
    "admin":   {"*": ["read", "write", "execute", "admin"]},
    "analyst": {
        "model_outputs": ["read"],
        "audit_logs":    ["read"],
        "trust_scores":  ["read"],
    },
    "developer": {
        "model_outputs": ["read", "execute"],
        "trust_scores":  ["read", "write"],
        "audit_logs":    ["read"],
    },
    "auditor": {
        "audit_logs":   ["read"],
        "trust_scores": ["read"],
    },
}


def evaluate_access(request: AccessRequest) -> AccessDecision:
    """Legacy endpoint handler — delegates to :func:`check_access` for scoring."""
    result = check_access(
        caller_id=request.user_id,
        resource=request.resource,
        action=request.action,
    )
    return AccessDecision(
        allowed=result.action_permitted,
        reason=result.recommendation,
        score=result.access_score,
    )
