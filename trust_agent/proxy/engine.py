"""
Agent B Proxy Engine — Two-Checkpoint Invisible Proxy for AI Agent Governance.

Architecture:
  Every request destined for Agent A is intercepted by Agent B at two points:
  • Checkpoint 1 (INTENT)  — before Agent A receives the request
  • Checkpoint 2 (OUTPUT)  — before the user receives Agent A's response

Agent A never knows Agent B exists.
"""
import json
import random
import re
import string
import time
import uuid
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo

from trust_agent.intelligence.hybrid_engine import HybridIntelligenceEngine, HybridResult
from trust_agent.intelligence.text_router import TextRouter as _TextRouter
from trust_agent.pillars.access_control import detect_role as _detect_role, detect_resource as _detect_resource

# India Standard Time — UTC+5:30 (no DST)
_IST = ZoneInfo("Asia/Kolkata")
from typing import Any

import structlog

from trust_agent.pillars.privacy import analyze_and_anonymize
from trust_agent.pillars.regulatory_compliance import check_compliance
from trust_agent.pillars.security import check_security

log = structlog.get_logger()

# ── In-memory session store ────────────────────────────────────────────────
_SESSIONS: dict[str, dict] = {}

# ── Session velocity / anomaly tracker ────────────────────────────────────
_session_tracker: dict = {}

# ── Rule categories ────────────────────────────────────────────────────────
_CRITICAL_RULES  = {
    "unknown_agent_block", "injection_in_task", "unknown_caller_block",
    "velocity_attack",
    # Regulatory hard stops — any match is an unconditional BLOCK
    "eu_ai_act_prohibited", "india_dpdp_absolute", "uae_pdpl_absolute",
    "ksa_pdpl_absolute", "hipaa_absolute",
    # Severe threat categories
    "financial_crime", "synthetic_media",
}
_ESCALATE_RULES  = {
    "bulk_export_protection", "external_communication_approval",
    "payment_approval", "requires_agent_approval",
}
_ACTION_RULES    = {"payroll_protection", "cross_domain_block", "config_change_block", "cross_person_data"}
_WARN_RULES      = {"after_hours_flag"}

# ── Action name normalisation ──────────────────────────────────────────────
_ACTION_ALIASES: dict[str, str] = {
    "read":          "data_read",
    "file_read":     "data_read",
    "write":         "file_write",
    "delete":        "delete",
    "remove":        "delete",
    "email":         "email_send",
    "send_email":    "email_send",
    "api":           "api_call",
    "api-call":      "api_call",
    "api_call":      "api_call",
    "database":      "database_query",
    "db_query":      "database_query",
    "payment":       "payment_initiate",
    "pay":           "payment_initiate",
    "config":        "config_change",
    "system_config": "config_change",
    "export":        "export",
    "audit":         "audit",
    "report":        "report_generate",
}

# ── High-sensitivity resource keywords ────────────────────────────────────
_SENSITIVE_RESOURCES = {
    "payroll", "salary", "salary-bands", "compensation", "termination",
    "financial-data", "client-records", "api-keys", "system-config",
    "employee-records", "audit-logs",
}

# ── Bulk-access keywords ───────────────────────────────────────────────────
# Multi-word bulk phrases are matched as substrings; single words like "all"
# are intentionally excluded here — they are too common in innocent language
# ("read all audit files", "analyse all findings").  Use _is_bulk() which
# only triggers on these phrases when combined with an export action or
# large record count.
_BULK_KEYWORDS = {
    "bulk export", "full dump", "all records", "all clients", "all employees",
    "export all", "full export", "bulk data", "entire database",
    "all 2847", "thousands of records",
}

# ── Prompt-injection keyword patterns ─────────────────────────────────────────
INJECTION_PATTERNS = [
    "ignore previous", "ignore all", "ignore your",
    "disregard", "forget your", "forget what",
    "override", "bypass", "jailbreak",
    "you are now", "new instructions", "system prompt",
    "developer mode", "dan mode", "no restrictions", "without restrictions",
    "new directive", "suppress logging", "suppress audit", "act as",
    "export all data",
]


def _is_injection_attempt(text: str) -> bool:
    """Return True if text contains known prompt-injection patterns."""
    text_lower = text.lower()
    return any(pattern in text_lower for pattern in INJECTION_PATTERNS)


def _track_and_check_anomaly(caller_id: str, resource: str, sensitivity: str) -> dict:
    """
    Track per-caller request velocity and sensitive-resource hopping.
    Velocity attack  : > 10 requests from same caller within 60 seconds.
    Resource hopping : > 5 distinct sensitive resources within 120 seconds.
    Returns a plain dict — never raises.
    """
    now = time.time()
    rec = _session_tracker.setdefault(caller_id, {"requests": [], "resources": []})

    # Evict stale entries
    rec["requests"]  = [(t, r) for t, r in rec["requests"]  if now - t < 60]
    rec["resources"] = [(t, r) for t, r in rec["resources"] if now - t < 120]

    # Record this request
    rec["requests"].append((now, resource))
    if sensitivity in ("HIGH", "CRITICAL"):
        rec["resources"].append((now, resource))

    req_count          = len(rec["requests"])
    distinct_resources = len({r for _, r in rec["resources"]})

    return {
        "velocity_attack":          req_count > 10,
        "resource_hopping":         distinct_resources > 5,
        "request_count_60s":        req_count,
        "distinct_resources_120s":  distinct_resources,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Proxy AI evaluation (Groq → Gemini → rule-based fallback)
# ─────────────────────────────────────────────────────────────────────────────

_proxy_evaluator = None   # lazy singleton

_PROXY_INTENT_PROMPT = """\
You are an enterprise AI governance expert. Evaluate whether an AI agent request is legitimate and safe.

Agent: {agent_id} — {agent_display}
Caller: {caller_id} (detected role: {caller_role})
Trigger: {trigger_type}
Task: {task}
Actions: {actions}

Score the intent 0-100 where 100=perfectly legitimate routine task, 0=clear malicious/policy-violating intent.
- 85-100: normal business request
- 60-84 : slightly unusual, light monitoring appropriate
- 35-59 : concerning, warrants scrutiny
- 0-34  : high-risk — injection, exfiltration, impersonation, or clear policy breach

Consider: task appropriateness for this agent type, action proportionality, exfiltration signs, social engineering.

Respond ONLY with this JSON (no markdown, no code fences):
{{
  "intent_score": <0-100>,
  "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "reasoning": "<2-3 sentence assessment>",
  "red_flags": ["<specific concern or empty list>"]
}}"""

_PROXY_OUTPUT_PROMPT = """\
You are an enterprise AI governance expert. Evaluate whether an AI agent's output is safe to release.

Agent: {agent_id} — {agent_display}
Caller role: {caller_role}
Original task: {task}

Agent output (first 1500 chars):
\"\"\"{output_preview}\"\"\"

Score the output safety 0-100 where 100=completely clean professional output, 0=critical violation.
- 85-100: clean, appropriate, safe to release
- 60-84 : minor concerns, can release with monitoring
- 35-59 : significant concerns — possible PII or compliance issues
- 0-34  : critical — clear PII exposure, compliance breach, or injection artefacts

Respond ONLY with this JSON (no markdown, no code fences):
{{
  "output_score": <0-100>,
  "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "reasoning": "<2-3 sentence assessment>",
  "concerns": ["<specific issue found or empty list>"]
}}"""


def _get_proxy_evaluator():
    """Lazy-load the multi-provider AI evaluator singleton."""
    global _proxy_evaluator
    if _proxy_evaluator is None:
        try:
            from trust_agent.intelligence.evaluator import GeminiEvaluator  # noqa: PLC0415
            _proxy_evaluator = GeminiEvaluator()
        except Exception as exc:
            log.warning("proxy_evaluator_init_failed", error=str(exc)[:120])
            _proxy_evaluator = object()  # sentinel — avoids retrying
    return _proxy_evaluator


_main_evaluator = None  # lazy singleton for pillar-style evaluate() calls


def _get_main_evaluator():
    """
    Lazy-load the ClaudeEvaluator (alias for GeminiEvaluator) singleton.
    This uses the same evaluator that the intelligence pillars use, ensuring
    it picks up the API keys loaded via load_dotenv(override=True) in its __init__.
    Returns None if init fails so callers can skip gracefully.
    """
    global _main_evaluator
    if _main_evaluator is None:
        try:
            from trust_agent.intelligence.evaluator import ClaudeEvaluator  # noqa: PLC0415
            _main_evaluator = ClaudeEvaluator()
            print("[PROXY] Main evaluator initialized successfully")
        except Exception as exc:
            log.warning("main_evaluator_init_failed", error=str(exc)[:120])
            _main_evaluator = object()  # sentinel — avoids retrying
    # Return None for the sentinel (object() has no 'evaluate' attr)
    if not hasattr(_main_evaluator, "evaluate"):
        return None
    return _main_evaluator


_hybrid_engine: HybridIntelligenceEngine | None = None  # lazy singleton


def _get_hybrid_engine() -> HybridIntelligenceEngine:
    """Return the module-level HybridIntelligenceEngine singleton."""
    global _hybrid_engine
    if _hybrid_engine is None:
        _hybrid_engine = HybridIntelligenceEngine()
        print("[Proxy] HybridIntelligenceEngine initialised")
    return _hybrid_engine


def _safe_parse_json(raw_text: str, context: str = "") -> dict | None:
    """
    Safe JSON parser for proxy engine responses.
    Returns None instead of raising on any failure.
    Strips markdown fences and detects provider error responses.
    """
    try:
        if not raw_text:
            return None

        cleaned = raw_text.strip()

        for fence in ("```json", "```JSON", "```"):
            if cleaned.startswith(fence):
                cleaned = cleaned[len(fence):]
                break
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        _error_phrases = (
            "internal server error", "service unavailable", "bad gateway",
            "too many requests", "rate limit exceeded", "unauthorized", "forbidden",
        )
        cleaned_lower = cleaned.lower()
        if len(cleaned) < 200 and any(p in cleaned_lower for p in _error_phrases):
            print(f"[ProxyParser] Provider error ({context}): {cleaned[:100]}")
            return None

        if not cleaned.startswith("{"):
            print(f"[ProxyParser] Non-JSON ({context}): {cleaned[:100]}")
            return None

        return json.loads(cleaned)

    except Exception as exc:
        print(f"[ProxyParser] Failed ({context}): {exc}")
        return None


def _ai_proxy_call(prompt_text: str) -> tuple[dict, str]:
    """
    Direct AI API call for proxy-specific evaluation.
    Returns (parsed_json_dict, provider_name).
    Falls back to ({}, 'none') when AI is unavailable or fails.
    """
    ev = _get_proxy_evaluator()

    # Check if the evaluator is a real GeminiEvaluator
    if not hasattr(ev, "groq_client"):
        return {}, "none"

    if ev.mock_mode:          # type: ignore[attr-defined]
        return {}, "none"

    sys_msg = (
        "You are an AI governance and enterprise compliance expert. "
        "Respond ONLY with valid JSON. Do NOT include text or markdown outside the JSON."
    )

    # ── Try Groq (primary) ────────────────────────────────────────────────
    if ev.groq_client:        # type: ignore[attr-defined]
        try:
            resp = ev.groq_client.chat.completions.create(  # type: ignore[attr-defined]
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": sys_msg},
                    {"role": "user",   "content": prompt_text},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=600,
            )
            parsed = _safe_parse_json(resp.choices[0].message.content, "groq")
            if parsed:
                return parsed, "groq"
            log.warning("proxy_groq_parse_failed")
        except Exception as exc:
            log.warning("proxy_groq_call_failed", error=str(exc)[:200])

    # ── Try Gemini (fallback) ─────────────────────────────────────────────
    if ev.gemini_client:      # type: ignore[attr-defined]
        try:
            _gemini_model = getattr(ev, "_gemini_model", "gemini-2.0-flash")
            resp = ev.gemini_client.models.generate_content(  # type: ignore[attr-defined]
                model=_gemini_model,
                contents=sys_msg + "\n\n" + prompt_text,
            )
            parsed = _safe_parse_json(resp.text, "gemini")
            if parsed:
                return parsed, "gemini"
            log.warning("proxy_gemini_parse_failed")
        except Exception as exc:
            log.warning("proxy_gemini_call_failed", error=str(exc)[:200])

    return {}, "none"


# ─────────────────────────────────────────────────────────────────────────────
# Role detection — single source of truth in trust_agent.pillars.access_control
# _detect_role is imported at the top of this file:
#   from trust_agent.pillars.access_control import detect_role as _detect_role
# ─────────────────────────────────────────────────────────────────────────────


def _parse_hour(timestamp: str) -> int:
    """Extract hour (0-23) in IST (Asia/Kolkata, UTC+5:30) from ISO timestamp.
    Falls back to current IST time if the timestamp cannot be parsed.
    """
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.astimezone(_IST).hour
    except Exception:
        return datetime.now(_IST).hour


def _mk_audit_id() -> str:
    now    = datetime.now(timezone.utc)
    suffix = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
    return f"TXN-{now.strftime('%Y%m%d-%H%M%S')}-{suffix}"


def _norm_action(action: str) -> str:
    return _ACTION_ALIASES.get(action.lower().strip(), action.lower().strip())


def _is_bulk(task: str, actions: list[dict]) -> bool:
    """
    Return True only for genuine bulk-extraction attempts.
    Multi-word phrases from _BULK_KEYWORDS, export actions, or very large
    record counts trigger this.  Single words like "all" in normal task
    language ("read all audit files") do NOT trigger this.
    """
    t = task.lower()
    # Multi-word bulk phrases matched as substrings (safe — all phrases are specific)
    if any(kw in t for kw in _BULK_KEYWORDS):
        return True
    for a in actions:
        resource = a.get("resource", "").lower()
        action   = a.get("action",   "").lower()
        # Only flag resource keywords when the action is explicitly export/dump
        if action in ("export", "dump", "extract") and any(
            kw in resource for kw in ("all", "bulk", "entire", "full")
        ):
            return True
        # Very large record counts always flag regardless of action
        if a.get("record_count", 0) > 500:
            return True
        tgt = a.get("target", "").lower()
        if any(kw in tgt for kw in _BULK_KEYWORDS):
            return True
    return False


def _is_external(target: str) -> bool:
    internal = {"@internal", "@company.com", "@uniqus.com", "@corp", "internal", ""}
    t = target.lower()
    if not t:
        return False
    return not any(i in t for i in internal)


# ─────────────────────────────────────────────────────────────────────────────
# AgentProxy
# ─────────────────────────────────────────────────────────────────────────────

class AgentProxy:

    # ── Agent registry ─────────────────────────────────────────────────────

    AGENT_REGISTRY: dict[str, dict] = {
        "hr-agent": {
            "display_name":          "HR Agent",
            "allowed_actions":       ["data_read", "report_generate", "email_send", "file_read"],
            "allowed_resources":     ["employee-records", "hr-policies", "recruitment-data",
                                      "performance-data", "approved-reports"],
            "blocked_resources":     ["financial-data", "system-config", "api-keys",
                                      "client-records", "audit-logs"],
            "max_records_per_query": 50,
            "requires_approval_for": ["payroll-data", "termination-records", "salary-bands"],
            "trust_baseline":        80,
        },
        "finance-agent": {
            "display_name":          "Finance Agent",
            "allowed_actions":       ["data_read", "report_generate", "database_query",
                                      "file_read", "file_write", "export"],
            "allowed_resources":     ["financial-data", "invoices", "budgets",
                                      "financial-reports", "accounts", "audit-logs"],
            "blocked_resources":     ["employee-records", "system-config", "api-keys",
                                      "payroll-data"],
            "max_records_per_query": 200,
            "requires_approval_for": ["payment_initiate", "bulk-financial-export",
                                      "client-financial-records"],
            "trust_baseline":        85,
        },
        "legal-agent": {
            "display_name":          "Legal Agent",
            "allowed_actions":       ["data_read", "report_generate", "file_read", "file_write"],
            "allowed_resources":     ["contracts", "legal-documents", "compliance-data",
                                      "approved-reports", "regulatory-reports"],
            "blocked_resources":     ["financial-data", "system-config", "payroll-data",
                                      "employee-records"],
            "max_records_per_query": 100,
            "requires_approval_for": ["email_send", "contract-amendment", "external-communication"],
            "trust_baseline":        82,
        },
        "audit-agent": {
            "display_name":          "Audit Agent",
            "allowed_actions":       ["data_read", "report_generate", "database_query",
                                      "audit", "file_read", "export"],
            "allowed_resources":     ["audit-logs", "compliance-data", "financial-data",
                                      "risk-register", "client-records", "reports"],
            "blocked_resources":     ["system-config", "api-keys", "payroll-data"],
            "max_records_per_query": 500,
            "requires_approval_for": ["bulk-client-data-export", "financial-records-external-share"],
            "trust_baseline":        88,
        },
        "data-agent": {
            "display_name":          "Data Agent",
            "allowed_actions":       ["data_read", "database_query", "report_generate", "export"],
            "allowed_resources":     ["approved-reports", "public-data", "research-data",
                                      "project-data"],
            "blocked_resources":     ["payroll-data", "financial-data", "client-records",
                                      "employee-records", "system-config", "api-keys"],
            "max_records_per_query": 100,
            "requires_approval_for": ["bulk-export", "client-data"],
            "trust_baseline":        70,
        },
        "unknown-agent": {
            "display_name":          "Unknown Agent",
            "allowed_actions":       [],
            "allowed_resources":     [],
            "blocked_resources":     "all",
            "max_records_per_query": 0,
            "requires_approval_for": "all",
            "trust_baseline":        0,
        },
    }

    # ── Guardrail rule definitions (descriptive — evaluation is code below) ──

    GUARDRAIL_RULES: dict[str, dict] = {
        # ── Access control & identity ──────────────────────────────────────
        "payroll_protection":               {"description": "Payroll data requires HR Manager or above", "decision": "BLOCK", "framework": "Internal Policy"},
        "cross_person_data":                {"description": "Accessing another employee's personal data without management role", "decision": "BLOCK", "framework": "Internal Policy"},
        "bulk_export_protection":           {"description": "Bulk data export requires Partner/Director approval", "decision": "ESCALATE", "framework": "Internal Policy"},
        "unknown_agent_block":              {"description": "Unregistered agents are blocked entirely", "decision": "BLOCK", "framework": "Internal Policy"},
        "unknown_caller_block":             {"description": "Unknown callers blocked from sensitive resources", "decision": "BLOCK", "framework": "Internal Policy"},
        "after_hours_flag":                 {"description": "Access outside business hours flagged", "decision": "WARN", "framework": "Internal Policy"},
        "cross_domain_block":               {"description": "Agents cannot access resources outside their domain", "decision": "BLOCK", "framework": "Internal Policy"},
        "external_communication_approval":  {"description": "External communications require senior approval", "decision": "ESCALATE", "framework": "Internal Policy"},
        "payment_approval":                 {"description": "Payment initiation requires CFO approval", "decision": "ESCALATE", "framework": "Internal Policy"},
        "config_change_block":              {"description": "Configuration changes restricted to Admin/CTO", "decision": "BLOCK", "framework": "Internal Policy"},
        "requires_agent_approval":          {"description": "Resource requires senior approval for this agent type", "decision": "ESCALATE", "framework": "Internal Policy"},
        # ── Security threats ───────────────────────────────────────────────
        "injection_in_task":                {"description": "Prompt injection detected in agent task", "decision": "BLOCK", "framework": "OWASP LLM Top 10 2025"},
        "velocity_attack":                  {"description": "Abnormal request velocity (>10 req/60s) — possible DoS or scraping", "decision": "BLOCK", "framework": "OWASP LLM10"},
        # ── Output safety ─────────────────────────────────────────────────
        "pii_in_output":                    {"description": "PII found in output outside permitted scope", "decision": "REDACT", "framework": "GDPR / India DPDP"},
        "compliance_violation_in_output":   {"description": "Compliance violation detected in agent output", "decision": "BLOCK", "framework": "Regulatory"},
        # ── OWASP LLM Top 10 (2025) ───────────────────────────────────────
        "owasp_llm01":   {"description": "LLM01 — Prompt Injection: attempt to override system instructions", "decision": "BLOCK", "framework": "OWASP LLM Top 10 2025"},
        "owasp_llm02":   {"description": "LLM02 — Sensitive Information Disclosure: exfiltrating training data or system internals", "decision": "BLOCK", "framework": "OWASP LLM Top 10 2025"},
        "owasp_llm04":   {"description": "LLM04 — Data/Model Poisoning: attempt to corrupt model knowledge", "decision": "BLOCK", "framework": "OWASP LLM Top 10 2025"},
        "owasp_llm06":   {"description": "LLM06 — Excessive Agency: agent instructed to act autonomously beyond scope", "decision": "BLOCK", "framework": "OWASP LLM Top 10 2025"},
        "owasp_llm07":   {"description": "LLM07 — System Prompt Leakage: request to reveal system prompt / instructions", "decision": "BLOCK", "framework": "OWASP LLM Top 10 2025"},
        "owasp_llm08":   {"description": "LLM08 — Vector & Embedding Manipulation: poisoning RAG knowledge store", "decision": "BLOCK", "framework": "OWASP LLM Top 10 2025"},
        "owasp_llm09":   {"description": "LLM09 — Misinformation / Fabrication: generating fake news or forged evidence", "decision": "BLOCK", "framework": "OWASP LLM Top 10 2025"},
        "owasp_llm10":   {"description": "LLM10 — Unbounded Consumption: infinite loop or resource exhaustion attack", "decision": "BLOCK", "framework": "OWASP LLM Top 10 2025"},
        # ── Regulatory hard stops ─────────────────────────────────────────
        "eu_ai_act_prohibited":  {"description": "EU AI Act Art.5 — prohibited AI practice (social scoring, biometric surveillance, emotion recognition)", "decision": "BLOCK", "framework": "EU AI Act 2024"},
        "india_dpdp_absolute":   {"description": "India DPDP Act 2023 — cross-border transfer / processing without consent (penalty up to ₹250 crore)", "decision": "BLOCK", "framework": "India DPDP 2023"},
        "uae_pdpl_absolute":     {"description": "UAE PDPL 2022 — personal data transfer outside UAE without TDRA approval (penalty up to AED 20M)", "decision": "BLOCK", "framework": "UAE PDPL 2022"},
        "ksa_pdpl_absolute":     {"description": "KSA PDPL 2021 — transfer of Saudi personal data without NDMO approval (penalty up to SAR 5M)", "decision": "BLOCK", "framework": "KSA PDPL 2021"},
        "hipaa_absolute":        {"description": "HIPAA — sharing or selling PHI without patient authorisation (penalty up to $1.9M/violation)", "decision": "BLOCK", "framework": "HIPAA"},
        # ── Threat categories ─────────────────────────────────────────────
        "financial_crime":           {"description": "Financial crime pattern: money laundering, structuring, BEC, ghost employees, trade-based laundering", "decision": "BLOCK", "framework": "FATF / AML-CFT"},
        "synthetic_media":           {"description": "Synthetic media / deepfake generation: deepfake video, voice clone, forged signatures", "decision": "BLOCK", "framework": "EU AI Act / Internal Policy"},
        "shadow_ai_detection":       {"description": "Shadow AI usage detected: undisclosed ChatGPT/Copilot/Bard use in enterprise context", "decision": "WARN", "framework": "AI Governance Policy"},
        "multi_agent_trust_boundary":{"description": "Multi-agent trust boundary violation: agent acting on unverified instructions from another agent", "decision": "WARN", "framework": "OWASP LLM Top 10 2025 / Agentic AI"},
    }

    # ── Role hierarchy — numeric levels for access decisions ─────────────────
    # Higher = more authority.  Used for payroll / sensitive-resource checks.
    ROLE_HIERARCHY: dict[str, int] = {
        "ceo":                10,
        "partner":             9,
        "admin":               9,   # IT admin has near-top system access
        "director":            8,   # Director ≥ all manager levels
        "cfo":                 8,
        "cto":                 8,
        "coo":                 8,
        "ciso":                8,
        "senior_manager":      7,
        "compliance_manager":  7,
        "risk_manager":        7,
        "finance_manager":     7,
        "hr_manager":          7,   # Payroll minimum = 7
        "it_manager":          7,
        "legal_manager":       7,
        "audit_manager":       7,
        "manager":             6,
        "lead_analyst":        5,
        "senior_analyst":      5,
        "senior_consultant":   5,
        "auditor":             5,
        "external_auditor":    4,
        "analyst":             4,
        "consultant":          4,
        "developer":           4,
        "scheduler":           3,
        "associate":           3,
        "support":             2,
        "operations":          2,
        "intern":              1,
        "client":              1,
        "vendor":              1,
        "guest":               0,
        "unknown":             0,
    }
    # Minimum role level to access payroll / compensation resources
    _PAYROLL_MIN_LEVEL: int = 7

    # ────────────────────────────────────────────────────────────────────────
    # Checkpoint 1 — Intent evaluation
    # ────────────────────────────────────────────────────────────────────────

    def checkpoint_intent(self, request: dict) -> dict:
        """
        Evaluate the intent of an agent request before it reaches Agent A.
        Returns a structured result with decision, violations, and guardrail evaluations.
        """
        ts        = request.get("timestamp") or datetime.now(timezone.utc).isoformat()
        session_id= request.get("session_id") or str(uuid.uuid4())
        audit_id  = _mk_audit_id()
        cp_id     = f"CP1-{session_id[:8].upper()}"

        agent_id     = request.get("agent_id", "unknown-agent")
        caller_id    = request.get("caller_id", "unknown")
        task_desc    = request.get("task_description", "")
        raw_actions  = request.get("requested_actions", [])
        trigger_type = request.get("trigger_type", "manual")
        hour         = _parse_hour(ts)

        # ── 1. Resolve agent profile ──────────────────────────────────────
        is_unknown    = agent_id not in self.AGENT_REGISTRY
        reg_key       = agent_id if not is_unknown else "unknown-agent"
        agent_profile = self.AGENT_REGISTRY[reg_key]

        # ── 2. Detect caller role ─────────────────────────────────────────
        caller_role = _detect_role(caller_id)

        # ── 3. Normalise actions ──────────────────────────────────────────
        actions: list[dict] = []
        for a in raw_actions:
            actions.append({
                "action":       _norm_action(a.get("action", "data_read")),
                "resource":     a.get("resource", ""),
                "target":       a.get("target", ""),
                "record_count": int(a.get("record_count", 0)),
            })

        # ── 4. Hybrid Intelligence evaluation ─────────────────────────────────
        # Three-tier system: Tier 1 = definitive rules (0 API calls, ~70% of cases),
        # Tier 2 = AI only for ambiguous cases, Tier 3 = enhanced rules fallback.
        _hybrid = _get_hybrid_engine()
        hybrid_result = _hybrid.evaluate(
            text=task_desc,
            context={
                "agent_id":          agent_id,
                "caller_role":       caller_role,
                "caller_id":         caller_id,
                "trigger_type":      trigger_type,
                "requested_actions": raw_actions,
                "timestamp":         ts,
            },
        )
        print(f"[Proxy] Hybrid tier: {hybrid_result.tier_used} | API calls: {hybrid_result.api_calls_made}")

        # Map hybrid result → internal variables used by the rest of this function
        security_score     = hybrid_result.scores.get("security", 85.0)
        _early_ai_provider = hybrid_result.tier_used.lower().replace("_", "-")
        _early_ai_data: dict = {
            "intent_score": security_score,
            "risk_level": (
                "CRITICAL" if security_score < 20 else
                "HIGH"     if security_score < 40 else
                "MEDIUM"   if security_score < 70 else
                "LOW"
            ),
            "reasoning":  hybrid_result.reasoning,
            "red_flags":  [
                v.get("description", "")[:80]
                for v in hybrid_result.violations[:3]
                if v.get("description")
            ],
        }

        # ── 4b. Wire hybrid OWASP / regulatory violations → guardrails_applied ─
        # Collect which OWASP / regulatory rules were triggered by the hybrid engine
        # so they appear in the Guardrails Evaluated card in the UI (CP1 result).
        _OWASP_REGULATORY_RULES = {
            "owasp_llm01", "owasp_llm02", "owasp_llm04", "owasp_llm06",
            "owasp_llm07", "owasp_llm08", "owasp_llm09", "owasp_llm10",
            "eu_ai_act_prohibited", "india_dpdp_absolute", "uae_pdpl_absolute",
            "ksa_pdpl_absolute", "hipaa_absolute",
            "financial_crime", "synthetic_media",
            "shadow_ai_detection", "multi_agent_trust_boundary",
        }
        _triggered_hybrid_rules: set[str] = set()
        _owasp_reg_guardrails: list[dict] = []   # added to guardrails_applied later

        for hv in hybrid_result.violations:
            rule = hv.get("guardrail_rule", "")
            if rule in _OWASP_REGULATORY_RULES:
                _triggered_hybrid_rules.add(rule)
                _is_block_rule = rule not in {"shadow_ai_detection", "multi_agent_trust_boundary"}
                _owasp_reg_guardrails.append({
                    "rule_name": rule,
                    "triggered": True,
                    "decision":  "BLOCK" if _is_block_rule else "WARN",
                    "reason":    hv.get("description", f"Pattern matched: {rule}"),
                })

        # PASS entries for every rule that was NOT triggered
        for rule in _OWASP_REGULATORY_RULES:
            if rule not in _triggered_hybrid_rules:
                _owasp_reg_guardrails.append({
                    "rule_name": rule,
                    "triggered": False,
                    "decision":  "PASS",
                    "reason":    "No matching pattern detected in task.",
                })

        # ── 4c. Session anomaly detection ─────────────────────────────────
        _first_resource = raw_actions[0].get("resource", "") if raw_actions else ""
        _resource_sensitivity = (
            "HIGH" if any(kw in _first_resource.lower() for kw in _SENSITIVE_RESOURCES)
            else "LOW"
        )
        _anomaly = _track_and_check_anomaly(caller_id, _first_resource, _resource_sensitivity)

        # ── 5. Evaluate guardrail rules ───────────────────────────────────
        guardrails_applied: list[dict] = []
        violations:         list[dict] = []
        blocked_actions:    list[dict] = []
        allowed_actions:    list[dict] = []
        escalation_required = False
        escalate_to:    str | None = None
        escalation_reason: str | None = None

        # Prepend OWASP / regulatory guardrail rows (shown at top of the card)
        guardrails_applied.extend(_owasp_reg_guardrails)

        # ── Session anomaly: velocity attack ──────────────────────────────
        if _anomaly["velocity_attack"]:
            guardrails_applied.append({
                "rule_name": "velocity_attack", "triggered": True,
                "decision":  "BLOCK",
                "reason":    (
                    f"Velocity attack detected: {_anomaly['request_count_60s']} requests "
                    f"in the last 60s from caller '{caller_id}'."
                ),
            })
            violations.append({
                "severity": "CRITICAL", "pillar": "security",
                "description": (
                    f"Velocity attack: {_anomaly['request_count_60s']} requests/60s from '{caller_id}'"
                ),
                "guardrail_rule": "velocity_attack",
            })
        else:
            guardrails_applied.append({
                "rule_name": "velocity_attack", "triggered": False,
                "decision":  "PASS",
                "reason":    f"Normal request velocity ({_anomaly['request_count_60s']} req/60s).",
            })

        # ── CRITICAL: Unknown agent ───────────────────────────────────────
        if is_unknown:
            guardrails_applied.append({
                "rule_name": "unknown_agent_block", "triggered": True,
                "decision": "BLOCK",
                "reason": f"Agent '{agent_id}' is not registered in the agent registry.",
            })
            violations.append({
                "severity": "CRITICAL", "pillar": "access_control",
                "description": f"Unregistered agent: '{agent_id}'",
                "guardrail_rule": "unknown_agent_block",
            })
        else:
            guardrails_applied.append({
                "rule_name": "unknown_agent_block", "triggered": False,
                "decision": "PASS", "reason": "Agent identity verified in registry.",
            })

        # ── CRITICAL: Prompt injection ────────────────────────────────────
        # Threshold of 25 (not 40) avoids false positives on innocent tasks
        # that the AI evaluator rates conservatively (e.g. "read all files").
        # Genuine injections ("ignore previous instructions") score < 10.
        if security_score < 25:
            guardrails_applied.append({
                "rule_name": "injection_in_task", "triggered": True,
                "decision": "BLOCK",
                "reason": f"Security score {security_score:.0f}/100 — potential prompt injection / adversarial content in task description.",
            })
            violations.append({
                "severity": "CRITICAL", "pillar": "security",
                "description": f"Possible prompt injection or adversarial content (security score {security_score:.0f})",
                "guardrail_rule": "injection_in_task",
            })
        else:
            guardrails_applied.append({
                "rule_name": "injection_in_task", "triggered": False,
                "decision": "PASS",
                "reason": f"Security score {security_score:.0f}/100 — no injection detected.",
            })

        # ── CRITICAL: Unknown caller accessing sensitive resources ─────────
        if caller_role == "unknown" and not is_unknown:
            sensitive_access = any(
                any(s in a["resource"].lower() for s in _SENSITIVE_RESOURCES)
                for a in actions
            )
            if sensitive_access:
                guardrails_applied.append({
                    "rule_name": "unknown_caller_block", "triggered": True,
                    "decision": "BLOCK",
                    "reason": f"Caller '{caller_id}' has no verified role — identity check required before accessing sensitive resources.",
                })
                violations.append({
                    "severity": "CRITICAL", "pillar": "access_control",
                    "description": f"Unverified caller '{caller_id}' attempting sensitive resource access",
                    "guardrail_rule": "unknown_caller_block",
                })

        # ── Per-action rule evaluation ────────────────────────────────────
        blocked_resources = agent_profile.get("blocked_resources", [])
        allowed_agent_actions = agent_profile.get("allowed_actions", [])
        requires_approval = agent_profile.get("requires_approval_for", [])

        for act in actions:
            action   = act["action"]
            resource = act["resource"]
            target   = act["target"]
            rc       = act["record_count"]
            action_blocked = False
            action_reason  = ""

            # Action not in agent's permitted list
            if not is_unknown and action not in allowed_agent_actions:
                action_blocked = True
                action_reason  = f"Action '{action}' not permitted for {agent_profile['display_name']}"
                guardrails_applied.append({
                    "rule_name": "action_not_permitted", "triggered": True,
                    "decision": "BLOCK",
                    "reason": action_reason,
                })
                violations.append({
                    "severity": "HIGH", "pillar": "access_control",
                    "description": action_reason,
                    "guardrail_rule": "action_not_permitted",
                })

            # Cross-domain: resource in agent's blocked list
            # Normalise separators so "financial_data" matches "financial-data"
            def _norm_res(s: str) -> str:
                return s.lower().replace("-", "_").replace(" ", "_")

            res_norm = _norm_res(resource)
            if blocked_resources == "all":
                cross_blocked = True
            elif blocked_resources:
                cross_blocked = any(
                    res_norm in _norm_res(br) or _norm_res(br) in res_norm
                    for br in blocked_resources
                )
            else:
                cross_blocked = False

            if cross_blocked and not is_unknown:
                action_blocked = True
                action_reason  = f"Resource '{resource}' is outside {agent_profile['display_name']}'s permitted domain"
                guardrails_applied.append({
                    "rule_name": "cross_domain_block", "triggered": True,
                    "decision": "BLOCK",
                    "reason": action_reason,
                })
                violations.append({
                    "severity": "HIGH", "pillar": "access_control",
                    "description": action_reason,
                    "guardrail_rule": "cross_domain_block",
                })

            # Payroll protection — hierarchy-based (level ≥ 7 = HR Manager or above)
            payroll_keywords = {"payroll", "salary", "salary-bands", "compensation", "termination-records"}
            is_payroll = any(kw in resource.lower() for kw in payroll_keywords)
            if is_payroll:
                _caller_level = self.ROLE_HIERARCHY.get(caller_role, 0)
                if _caller_level < self._PAYROLL_MIN_LEVEL:
                    action_blocked = True
                    action_reason  = (
                        f"Payroll / compensation data access denied — requires HR Manager or above "
                        f"(role: '{caller_role}', level {_caller_level}; minimum level {self._PAYROLL_MIN_LEVEL})"
                    )
                    guardrails_applied.append({
                        "rule_name": "payroll_protection", "triggered": True,
                        "decision": "BLOCK",
                        "reason": action_reason,
                    })
                    violations.append({
                        "severity": "CRITICAL", "pillar": "fairness",
                        "description": action_reason,
                        "guardrail_rule": "payroll_protection",
                    })
                else:
                    guardrails_applied.append({
                        "rule_name": "payroll_protection", "triggered": False,
                        "decision": "PASS",
                        "reason": (
                            f"Role '{caller_role}' (level {_caller_level}) meets payroll minimum "
                            f"(level {self._PAYROLL_MIN_LEVEL}) — access permitted with audit logging."
                        ),
                    })

            # Config change block — Director+ and admin/cto permitted
            _config_min_level = self.ROLE_HIERARCHY.get("cto", 8)
            if action == "config_change" and self.ROLE_HIERARCHY.get(caller_role, 0) < _config_min_level:
                action_blocked = True
                action_reason  = "System configuration changes restricted to Admin and CTO only"
                guardrails_applied.append({
                    "rule_name": "config_change_block", "triggered": True,
                    "decision": "BLOCK",
                    "reason": action_reason,
                })
                violations.append({
                    "severity": "HIGH", "pillar": "access_control",
                    "description": action_reason,
                    "guardrail_rule": "config_change_block",
                })

            # Bulk export protection
            is_bulk_act = (
                action in ("export",) and _is_bulk(task_desc, [act])
                or rc > 100
                or _is_bulk(task_desc, [act])
            )
            if is_bulk_act and not action_blocked:
                escalation_required = True
                if escalate_to is None:
                    escalate_to       = "partner"
                    escalation_reason = "Bulk data export requires Partner or Director approval"
                guardrails_applied.append({
                    "rule_name": "bulk_export_protection", "triggered": True,
                    "decision": "ESCALATE",
                    "reason": "Bulk data export (>100 records or 'all' target) requires Partner/Director approval",
                    "escalate_to": "partner",
                })
                violations.append({
                    "severity": "HIGH", "pillar": "compliance",
                    "description": f"Bulk export attempted: resource='{resource}' — escalation required",
                    "guardrail_rule": "bulk_export_protection",
                })

            # External communication approval
            if action == "email_send" and _is_external(target):
                escalation_required = True
                if escalate_to is None:
                    escalate_to       = "senior_manager"
                    escalation_reason = "External communications require Partner or Senior Manager approval"
                guardrails_applied.append({
                    "rule_name": "external_communication_approval", "triggered": True,
                    "decision": "ESCALATE",
                    "reason": f"External email to '{target}' requires senior approval",
                    "escalate_to": "senior_manager",
                })
                violations.append({
                    "severity": "HIGH", "pillar": "compliance",
                    "description": f"External communication to '{target}' without senior approval",
                    "guardrail_rule": "external_communication_approval",
                })

            # Payment approval
            if action == "payment_initiate":
                escalation_required = True
                if escalate_to is None:
                    escalate_to       = "cfo"
                    escalation_reason = "Payment initiation requires CFO approval regardless of role"
                guardrails_applied.append({
                    "rule_name": "payment_approval", "triggered": True,
                    "decision": "ESCALATE",
                    "reason": "All payment initiations require CFO approval",
                    "escalate_to": "cfo",
                })
                violations.append({
                    "severity": "HIGH", "pillar": "compliance",
                    "description": "Payment initiation without CFO approval",
                    "guardrail_rule": "payment_approval",
                })

            # Requires-approval-for check (skip if the action is already blocked)
            # Directors (level ≥ 8) and above can self-authorise — escalation waived.
            _req_caller_level = self.ROLE_HIERARCHY.get(caller_role, 0)
            if not action_blocked and requires_approval != "all":
                for ar in requires_approval:
                    if ar in resource.lower() or ar == action:
                        if _req_caller_level >= 8:
                            # Senior role — log access but do not escalate
                            guardrails_applied.append({
                                "rule_name": "requires_agent_approval", "triggered": False,
                                "decision": "NOTE",
                                "reason": (
                                    f"Role '{caller_role}' (level {_req_caller_level}) has sufficient authority — "
                                    f"escalation waived. Access logged for audit."
                                ),
                            })
                        else:
                            if not escalation_required:
                                escalation_required = True
                                escalate_to         = "partner"
                                escalation_reason   = (
                                    f"'{resource}' requires senior approval for "
                                    f"{agent_profile['display_name']} at role level {_req_caller_level}"
                                )
                            guardrails_applied.append({
                                "rule_name": "requires_agent_approval", "triggered": True,
                                "decision": "ESCALATE",
                                "reason": escalation_reason,
                                "escalate_to": "partner",
                            })
                            violations.append({
                                "severity": "MEDIUM", "pillar": "access_control",
                                "description": escalation_reason,
                                "guardrail_rule": "requires_agent_approval",
                            })
                        break

            if action_blocked:
                blocked_actions.append({
                    "action": action, "resource": resource, "reason": action_reason,
                })
            else:
                allowed_actions.append({"action": action, "resource": resource, "target": target})

        # ── After-hours check (IST) ───────────────────────────────────────
        now_ist      = datetime.now(_IST)
        ist_time_str = now_ist.strftime("%H:%M IST")
        is_after_hours = now_ist.hour < 7 or now_ist.hour > 22
        print(f"[TimeCheck] Current IST time: {ist_time_str}, after_hours={is_after_hours}, trigger={trigger_type}")

        if is_after_hours and trigger_type in ("autonomous", "scheduled"):
            # Autonomous/scheduled agents running out of hours — flag as violation
            guardrails_applied.append({
                "rule_name": "after_hours_flag", "triggered": True,
                "decision": "WARN",
                "reason": f"Autonomous agent running outside business hours ({ist_time_str}) — flagged for review.",
            })
            violations.append({
                "severity": "MEDIUM",
                "pillar": "security",
                "description": f"After-hours autonomous access at {ist_time_str} ({trigger_type} trigger)",
                "guardrail_rule": "after_hours_flag",
            })
        elif is_after_hours:
            # Human manually using the system after hours — permitted, just noted
            guardrails_applied.append({
                "rule_name": "after_hours_flag", "triggered": False,
                "decision": "NOTE",
                "reason": f"Request made outside business hours ({ist_time_str}) by human user — permitted.",
            })
        else:
            # Within business hours — no action needed
            guardrails_applied.append({
                "rule_name": "after_hours_flag", "triggered": False,
                "decision": "PASS",
                "reason": f"Within business hours ({ist_time_str}).",
            })

        # ── Deduplicate guardrails ────────────────────────────────────────
        seen_rules: set[str] = set()
        deduped_guardrails: list[dict] = []
        for g in guardrails_applied:
            key = (g["rule_name"], g.get("decision", ""))
            if key not in seen_rules:
                seen_rules.add(key)
                deduped_guardrails.append(g)
        guardrails_applied = deduped_guardrails

        # ── Merge hybrid violations (fairness / compliance / AI-detected) ──
        # Add violations from the hybrid engine that the rule-based engine
        # doesn't cover (e.g. gender bias, caste bias, GDPR pattern matches).
        _existing_grules = {v.get("guardrail_rule", "") for v in violations}
        for hv in hybrid_result.violations:
            hv_rule   = hv.get("guardrail_rule", "ai_detected")
            hv_pillar = hv.get("pillar", "security")
            # Always add fairness / compliance violations from hybrid engine;
            # skip security injection duplicates (already added by rule engine).
            if hv_pillar in ("fairness", "compliance", "privacy"):
                violations.append(hv)
            elif hv_rule == "ai_detected":
                violations.append(hv)
            elif hv_rule not in _existing_grules:
                violations.append(hv)

        # ── Compute rule-based trust score ───────────────────────────────
        rule_trust_score = self._compute_trust_score(
            agent_profile["trust_baseline"], violations
        )

        # ── Blend AI + rules (reuse early AI call — no second Groq call) ──
        ai_data      = _early_ai_data
        ai_provider  = _early_ai_provider
        ai_intent_score: float | None = None
        ai_reasoning: str = ""
        ai_red_flags: list = []
        # Determine if evaluator is in pure simulation mode (no keys loaded)
        _ev = _get_proxy_evaluator()
        _ai_mock_mode = not hasattr(_ev, "mock_mode") or _ev.mock_mode  # type: ignore[attr-defined]
        if ai_data:
            ai_intent_score = float(ai_data.get("intent_score", 75.0))
            ai_reasoning    = str(ai_data.get("reasoning", ""))
            ai_red_flags    = [str(f) for f in ai_data.get("red_flags", []) if f]
            # Blend: 65% AI + 35% rules
            blended = round((ai_intent_score * 0.65) + (rule_trust_score * 0.35), 1)
            # Hard CRITICAL rule violations always cap the score
            has_critical = any(v.get("guardrail_rule") in _CRITICAL_RULES for v in violations)
            trust_score  = min(blended, 15.0) if has_critical else blended
        else:
            trust_score  = rule_trust_score
            if _ai_mock_mode:
                ai_reasoning = "Simulation mode — add API key for AI evaluation."
            else:
                ai_reasoning = "AI evaluation attempted — using rule-based fallback. Check /debug/intelligence for provider status."

        # ── Make final decision ───────────────────────────────────────────
        decision, proceed, conditions = self._make_decision(
            violations, blocked_actions, allowed_actions,
            escalation_required, escalate_to,
            trust_score=trust_score,
        )

        # ── Status from trust score ───────────────────────────────────────
        status = "GREEN" if trust_score >= 75 else ("AMBER" if trust_score >= 40 else "RED")

        # ── Build result ──────────────────────────────────────────────────
        result: dict = {
            "session_id":          session_id,
            "checkpoint_id":       cp_id,
            "timestamp":           ts,
            "agent_id":            agent_id,
            "agent_display_name":  agent_profile["display_name"],
            "caller_id":           caller_id,
            "caller_role":         caller_role,
            "trigger_type":        trigger_type,
            "trust_score":         trust_score,
            "security_score":      security_score,
            "status":              status,
            "decision":            decision,
            "proceed":             proceed,
            "guardrails_applied":  guardrails_applied,
            "allowed_actions":     allowed_actions,
            "blocked_actions":     blocked_actions,
            "violations":          violations,
            "escalation_required": escalation_required,
            "escalate_to":         escalate_to,
            "escalation_reason":   escalation_reason,
            "conditions":          conditions,
            "hour_of_access":      hour,
            "audit_id":            audit_id,
            "task_description":    task_desc,
            # AI evaluation fields
            "ai_intent_score":     ai_intent_score,
            "ai_reasoning":        ai_reasoning,
            "ai_red_flags":        ai_red_flags,
            "ai_provider":         ai_provider,
            "ai_mock_mode":        _ai_mock_mode,
            "rule_trust_score":    rule_trust_score,
            # Hybrid engine metadata
            "hybrid_tier":         hybrid_result.tier_used,
            "hybrid_api_calls":    hybrid_result.api_calls_made,
        }

        # ── Store session ─────────────────────────────────────────────────
        _SESSIONS[session_id] = {
            "session_id":  session_id,
            "agent_id":    agent_id,
            "caller_id":   caller_id,
            "trigger_type":trigger_type,
            "created_at":  ts,
            "cp1":         result,
            "cp2":         None,
            "status": (
                "blocked"            if not proceed and not escalation_required else
                "escalation_pending" if escalation_required else
                "active"
            ),
        }

        log.info(
            "proxy_cp1_complete",
            session_id=session_id,
            agent_id=agent_id,
            caller_id=caller_id,
            decision=decision,
            trust_score=trust_score,
            violations=len(violations),
        )

        return result

    # ────────────────────────────────────────────────────────────────────────
    # Checkpoint 2 — Output evaluation
    # ────────────────────────────────────────────────────────────────────────

    def checkpoint_output(
        self,
        session_id:           str,
        output:               str,
        actions_actually_taken: list[str] | None = None,
    ) -> dict:
        """
        Evaluate Agent A's output before it reaches the end user.
        Scans for PII, compliance violations, over-disclosure, and scope violations.
        """
        ts    = datetime.now(timezone.utc).isoformat()
        cp_id = f"CP2-{session_id[:8].upper()}"

        session = _SESSIONS.get(session_id)
        if not session:
            return {
                "session_id":   session_id,
                "checkpoint_id": cp_id,
                "timestamp":    ts,
                "decision":     "BLOCK",
                "trust_score":  0.0,
                "status":       "RED",
                "original_output":  output,
                "approved_output":  "",
                "error":        f"Session '{session_id}' not found. Run Checkpoint 1 first.",
                "audit_id":     _mk_audit_id(),
            }

        cp1 = session["cp1"]
        audit_id = cp1.get("audit_id", _mk_audit_id())

        # ── 1. Scope violation check ──────────────────────────────────────
        scope_violations: list[dict] = []
        cp1_allowed = {a["action"] for a in cp1.get("allowed_actions", [])}
        taken       = set(actions_actually_taken or [])
        for act in taken:
            norm = _norm_action(act)
            if norm not in cp1_allowed and cp1_allowed:
                scope_violations.append({
                    "action":      act,
                    "description": f"Action '{act}' was taken but not authorised by Checkpoint 1",
                    "severity":    "HIGH",
                })

        # ── 2. PII scan on output ─────────────────────────────────────────
        # Only entity types that represent genuine, sensitive personal data
        # trigger CP2 REDACT decisions.  Non-personal types (dates, orgs,
        # locations, IP addresses) and high-false-positive US patterns are
        # excluded so that legitimate professional reports are not blocked.
        _ACTIONABLE_PII_TYPES = {
            # Indian PII — always actionable
            "IN_AADHAAR", "IN_PAN", "IN_VOTER_ID", "IN_MOBILE",
            "IN_IFSC", "IN_GSTIN",
            # Gulf region PII — always actionable
            "UAE_EMIRATES_ID", "KSA_NATIONAL_ID", "QATAR_QID", "UAE_MOBILE",
            # Universal PII — personal emails and financial
            "PHONE_NUMBER", "CREDIT_CARD", "IBAN_CODE",
            "MEDICAL_LICENSE", "US_SSN",
            # EMAIL_ADDRESS — privacy.py smart filter now excludes work emails;
            # only personal domains (@gmail/@yahoo/@hotmail) reach here
            "EMAIL_ADDRESS",
            # PERSON names — only at high confidence (see threshold below);
            # professional-context names (Dear Mr. X) excluded by privacy.py filter
            "PERSON",
        }
        # NOTE: DATE_TIME, LOCATION, NRP, URL, ORGANIZATION intentionally excluded —
        # they are never redacted and should not trigger REDACT decisions.
        _MIN_PII_CONFIDENCE = 0.6   # require reasonable confidence

        pii_result   = analyze_and_anonymize(output)
        pii_found    = [
            e for e in pii_result.entities_found
            if e.get("entity_type") in _ACTIONABLE_PII_TYPES
            and float(e.get("score", 0)) >= _MIN_PII_CONFIDENCE
            # PERSON entities require higher confidence to avoid false positives
            and not (e.get("entity_type") == "PERSON" and float(e.get("score", 0)) < 0.80)
        ]
        pii_count    = len(pii_found)
        critical_pii = [
            e for e in pii_found
            if e.get("entity_type") in {
                "IN_AADHAAR", "IN_PAN", "UAE_EMIRATES_ID",
                "KSA_NATIONAL_ID", "US_SSN", "CREDIT_CARD",
            }
        ]

        # ── 3. Compliance scan on output ──────────────────────────────────
        # Check if AI providers are working by inspecting the CP1 session result.
        # If the CP1 AI call returned data, providers are up; use AI compliance.
        # If not (429/404/timeout), skip AI compliance to avoid 90s retry cycle.
        _cp1_session = _SESSIONS.get(session_id, {})
        _cp1_ai_worked = bool(_cp1_session.get("cp1", {}).get("ai_provider", "none") != "none")
        comp_result     = check_compliance(output[:2000]) if (output.strip() and _cp1_ai_worked) else None
        comp_score      = getattr(comp_result, "compliance_score", 100.0) if comp_result else 100.0
        comp_violations = getattr(comp_result, "violations_found", {}) if comp_result else {}
        # When AI is unavailable, fall back to keyword-based compliance check
        if not comp_result and output.strip():
            _gdpr_kws = {"indefinitely", "waive gdpr", "retain all personal data",
                         "share personal data without", "waive any right", "waive erasure"}
            _output_lower = output.lower()
            if any(kw in _output_lower for kw in _gdpr_kws):
                comp_score = 20.0
                comp_violations = {"gdpr": ["explicit waiver of data subject rights"]}
            else:
                comp_score = 90.0
                comp_violations = {}

        # Only count frameworks where EXPLICIT violation strings were matched,
        # not merely trigger keywords (which fire on innocent business language).
        # A framework "violated" = at least one violation keyword found in text.
        # Compliance status thresholds:
        #   VIOLATED  — comp_score < 30  → BLOCK  (clear regulatory breach)
        #   FLAGGED   — 30 <= score < 55 → WARN   (possible concern, no block)
        #   MONITORED — 55 <= score < 75 → ALLOW  (keywords present, no violation)
        #   CLEAR     — score >= 75      → ALLOW
        explicit_violations = {
            fw: v_list for fw, v_list in comp_violations.items() if v_list
        }
        compliance_issues = list(explicit_violations.keys())[:6]
        # Compliance is only a hard BLOCK when score is critically low AND
        # there are explicit violation phrases (not just keyword triggers).
        compliance_violated = comp_score < 30 and bool(explicit_violations)

        # ── 4. Over-disclosure detection ──────────────────────────────────
        _overdisclosure_kws = {
            "aadhaar", "pan:", "account number", "ifsc", "bank account",
            "salary", "payroll", "emirates id", "national id",
        }
        over_disclosure = (
            pii_count > 5
            or any(kw in output.lower() for kw in _overdisclosure_kws)
        )

        # ── 4b. AI output evaluation ──────────────────────────────────────
        # Only call AI for CP2 when the output is long (>200 chars) AND
        # there are early signals of issues (pii_count > 0 OR compliance
        # score < 75). This avoids 4 sequential AI calls per intercept
        # which would cause timeout on free-tier Groq (30 RPM).
        _ai_out_worth_checking = (
            len(output) > 200
            and (pii_count > 0 or comp_score < 75)
        )
        # Determine mock_mode for CP2 result (same logic as CP1)
        _ev2 = _get_proxy_evaluator()
        _ai_mock_mode = not hasattr(_ev2, "mock_mode") or _ev2.mock_mode  # type: ignore[attr-defined]

        ai_output_score: float | None = None
        ai_out_reasoning: str = ""
        ai_out_concerns: list = []
        ai_out_provider: str = "none"
        if _ai_out_worth_checking:
            output_prompt = _PROXY_OUTPUT_PROMPT.format(
                agent_id      = cp1.get("agent_id", "unknown"),
                agent_display = cp1.get("agent_display_name", "Unknown Agent"),
                caller_role   = cp1.get("caller_role", "unknown"),
                task          = cp1.get("task_description", "")[:300]
                                or str(cp1.get("violations", ""))[:200],
                output_preview= output[:1500],
            )
            ai_out_data, ai_out_provider = _ai_proxy_call(output_prompt)
            if ai_out_data:
                ai_output_score  = float(ai_out_data.get("output_score", 75.0))
                ai_out_reasoning = str(ai_out_data.get("reasoning", ""))
                ai_out_concerns  = [str(c) for c in ai_out_data.get("concerns", []) if c]
            else:
                if _ai_mock_mode:
                    ai_out_reasoning = "Simulation mode — add API key for AI evaluation."
                else:
                    ai_out_reasoning = "AI evaluation attempted — using rule-based fallback. Check /debug/intelligence for provider status."
        else:
            ai_out_reasoning = "Output evaluation skipped — no PII or compliance issues detected."

        # ── 5. Decide output action ───────────────────────────────────────
        # Decision hierarchy (most severe first):
        #   BLOCK  — explicit compliance violation (score < 30 + violation phrases)
        #   REDACT — PII found that is outside permitted scope (or critical PII)
        #   WARN   — compliance concern (30 <= score < 55) or minor scope expansion
        #   ALLOW  — clean output, monitored-level compliance flags, no PII issues

        redactions_applied: list[str] = []
        approved_output    = output
        output_decision    = "ALLOW"
        compliance_status  = (
            "VIOLATED"  if comp_score <  30 else
            "FLAGGED"   if comp_score <  55 else
            "MONITORED" if comp_score <  75 else
            "CLEAR"
        )
        cp2_trust = cp1.get("trust_score", 70.0)

        # 5a. BLOCK — explicit compliance violation in output
        if compliance_violated and output.strip():
            output_decision = "BLOCK"
            approved_output = (
                "[OUTPUT BLOCKED BY AGENT B PROXY]\n\n"
                "This output was blocked because it contains content with explicit "
                f"regulatory compliance violations (compliance score: {comp_score:.0f}/100, "
                f"status: {compliance_status}).\n\n"
                f"Frameworks violated: {', '.join(compliance_issues[:3])}.\n\n"
                "Original output quarantined for compliance review. "
                f"Reference: {audit_id}"
            )
            cp2_trust = max(0.0, cp2_trust - 35)

        # 5b. REDACT — PII found in output (only when not already BLOCKED)
        elif pii_count > 0:
            output_decision    = "REDACT"
            approved_output    = pii_result.anonymized_text
            redactions_applied = [
                f"{e['entity_type']} at position {e['start']}-{e['end']}"
                for e in pii_found
            ]
            cp2_trust = max(0.0, cp2_trust - (len(critical_pii) * 10 + pii_count * 5))

        # 5c. WARN — flagged compliance concern (not an outright violation)
        elif compliance_status == "FLAGGED":
            output_decision = "WARN"
            cp2_trust = max(0.0, cp2_trust - 10)

        # 5d. Scope violations: escalate ALLOW→WARN (not REDACT) for minor overruns
        if scope_violations and output_decision == "ALLOW":
            output_decision = "WARN"
            cp2_trust = max(0.0, cp2_trust - len(scope_violations) * 10)

        cp2_trust = round(min(100.0, cp2_trust), 1)
        cp2_status = "GREEN" if cp2_trust >= 75 else ("AMBER" if cp2_trust >= 40 else "RED")

        result: dict = {
            "session_id":            session_id,
            "checkpoint_id":         cp_id,
            "timestamp":             ts,
            "trust_score":           cp2_trust,
            "status":                cp2_status,
            "decision":              output_decision,
            "original_output":       output,
            "approved_output":       approved_output,
            "redactions_applied":    redactions_applied,
            "pii_found_in_output":   [e["entity_type"] for e in pii_found],
            "pii_entities":          pii_found[:20],
            "pii_count":             pii_count,
            "critical_pii":          critical_pii,
            "over_disclosure_detected": over_disclosure,
            "scope_violations":      scope_violations,
            "compliance_score":      comp_score,
            "compliance_status":     compliance_status,
            "compliance_issues":     compliance_issues,
            "audit_id":              audit_id,
            # AI evaluation fields
            "ai_output_score":       ai_output_score,
            "ai_reasoning":          ai_out_reasoning,
            "ai_concerns":           ai_out_concerns,
            "ai_provider":           ai_out_provider,
            "ai_mock_mode":          _ai_mock_mode,
        }

        _SESSIONS[session_id]["cp2"]    = result
        _SESSIONS[session_id]["status"] = "completed"

        log.info(
            "proxy_cp2_complete",
            session_id=session_id,
            decision=output_decision,
            pii_count=pii_count,
            compliance_score=comp_score,
            scope_violations=len(scope_violations),
        )

        return result

    # ────────────────────────────────────────────────────────────────────────
    # Private helpers
    # ────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _compute_trust_score(baseline: float, violations: list[dict]) -> float:
        score = float(baseline)
        for v in violations:
            sev = v.get("severity", "LOW")
            score -= {"CRITICAL": 35, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(sev, 5)
        return round(max(0.0, min(100.0, score)), 1)

    @staticmethod
    def calculate_final_decision(
        pillar_scores: dict,
        hard_violations: list,
        hard_escalations: list,
        caller_role: str,
        resource_sensitivity: str,
    ) -> tuple[float, str]:
        """
        Foundation 4 — Unified Scoring Engine.
        Single canonical function that produces BOTH composite score AND decision.
        They are always consistent — no other code may override the decision independently.

        Returns (composite_score, decision).
        Decision values: ALLOW | ALLOW_WITH_RESTRICTIONS | WARN | ESCALATE | BLOCK
        """
        weights = {
            "security":       0.25,
            "fairness":       0.20,
            "privacy":        0.20,
            "compliance":     0.15,
            "access":         0.12,
            "explainability": 0.05,
            "resilience":     0.03,
        }
        composite, weight_used = 0.0, 0.0
        for pillar, weight in weights.items():
            score = pillar_scores.get(pillar, 100.0)
            composite += score * weight
            weight_used += weight
        composite = round(
            max(0.0, min(100.0, composite / weight_used if weight_used else composite)), 2
        )

        # Rule 1: Hard CRITICAL violations always BLOCK — score forced to RED range
        if hard_violations:
            critical = [v for v in hard_violations if v.get("severity") == "CRITICAL"]
            if critical:
                composite = min(composite, 20.0)
                return composite, "BLOCK"

        # Rule 2: Hard escalations
        if hard_escalations:
            return composite, "ESCALATE"

        # Rule 3: Score-based decisions — score and decision always consistent
        if composite >= 85:
            return composite, "ALLOW"
        if composite >= 65:
            return composite, "ALLOW_WITH_RESTRICTIONS"
        if composite >= 40:
            # AMBER range — WARN unless access control specifically fails
            if pillar_scores.get("access", 100) < 40:
                composite = min(composite, 39.0)
                return composite, "BLOCK"
            return composite, "WARN"
        # RED range — always BLOCK
        return composite, "BLOCK"

    @staticmethod
    def _make_decision(
        violations:     list[dict],
        blocked_acts:   list[dict],
        allowed_acts:   list[dict],
        escalation_req: bool,
        escalate_to:    str | None,
        trust_score:    float = 70.0,
    ) -> tuple[str, bool, str | None]:
        """
        Returns (decision, proceed, conditions).
        Delegates score-based decision logic to calculate_final_decision() —
        the canonical scoring engine (Foundation 4).

        Priority chain:
          1. CRITICAL rule violations → unconditional BLOCK
          2. Escalation required      → ESCALATE
          3. Mixed blocked+allowed    → ALLOW_WITH_RESTRICTIONS (structural)
          4. All blocked or no blocks → calculate_final_decision() score-based
        """
        # ── 1. Hard CRITICAL guardrail-rule violations always BLOCK ────────
        has_critical_rule = any(
            v.get("guardrail_rule") in _CRITICAL_RULES for v in violations
        )
        if has_critical_rule:
            return "BLOCK", False, None

        # ── 2. Escalation required ─────────────────────────────────────────
        if escalation_req:
            return "ESCALATE", False, f"Pending approval from {escalate_to}"

        # ── 3. Mixed (some actions allowed, some blocked) — structural ─────
        if blocked_acts and allowed_acts:
            acted        = [a["action"] for a in allowed_acts]
            blocked_desc = "; ".join(
                f"{b['action']} on {b['resource']}" for b in blocked_acts[:3]
            )
            return (
                "ALLOW_WITH_RESTRICTIONS",
                True,
                f"Permitted actions: {', '.join(set(acted))}. Blocked: {blocked_desc}",
            )

        # ── 4. Delegate to calculate_final_decision() for score-based cases ─
        has_critical_sev = any(v.get("severity") == "CRITICAL" for v in violations)
        # Access score: low when blocked+critical, partial when just blocked
        access_score = (
            15.0 if (blocked_acts and has_critical_sev) else
            45.0 if blocked_acts else
            90.0
        )
        pillar_scores = {
            "security": trust_score,
            "access":   access_score,
        }
        hard_viol = [v for v in violations if v.get("severity") == "CRITICAL"]
        _, decision = AgentProxy.calculate_final_decision(
            pillar_scores    = pillar_scores,
            hard_violations  = hard_viol,
            hard_escalations = [],
            caller_role      = "",
            resource_sensitivity = "",
        )

        proceed    = decision in ("ALLOW", "ALLOW_WITH_RESTRICTIONS", "WARN")
        conditions: str | None = None
        if decision == "ALLOW_WITH_RESTRICTIONS":
            if blocked_acts:
                blocked_desc = "; ".join(
                    f"{b['action']} on {b['resource']}" for b in blocked_acts[:3]
                )
                conditions = (
                    f"Requested actions were blocked ({blocked_desc}). "
                    "Intent is clean — request allowed with access restrictions applied."
                )
            else:
                conditions = "Request permitted with monitoring — trust score in AMBER range."
        elif decision == "WARN":
            conditions = "Request flagged for review — AMBER trust score. Monitoring applied."
        return decision, proceed, conditions


# ── Module-level singleton ────────────────────────────────────────────────
proxy = AgentProxy()
