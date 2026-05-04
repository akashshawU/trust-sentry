"""
Foundation 2 — Canonical Text Routing.

Single source of truth for which text each pillar evaluates.
All pillar calls in the proxy engine MUST use TextRouter to obtain
the correct input text — never evaluate arbitrary raw fields directly.
"""


class TextRouter:
    """
    CP1 (Intent Guard) evaluates task_description + contextual signals.
    CP2 (Output Guard) evaluates agent_output.
    Each pillar evaluates the text relevant to its concern.
    """

    # ── CP1 text ──────────────────────────────────────────────────────────────

    @staticmethod
    def get_cp1_text(request: dict) -> str:
        """
        Full text CP1 should evaluate.
        Combines task description with contextual signals that affect risk.
        """
        parts: list[str] = []

        if request.get("task_description"):
            parts.append(request["task_description"])

        # Autonomous / scheduled triggers add elevated-risk signal
        trigger = request.get("trigger_type", "manual")
        if trigger in ("autonomous", "scheduled"):
            parts.append(f"[Autonomous trigger: {trigger}]")

        # Action context adds specificity for injection / exfiltration checks
        for action in (request.get("requested_actions") or []):
            resource    = action.get("resource", "")
            action_type = action.get("action_type") or action.get("action", "")
            if resource and action_type:
                parts.append(f"[Action: {action_type} on {resource}]")

        return " ".join(parts)

    # ── Per-pillar CP1 text selectors ────────────────────────────────────────

    @staticmethod
    def get_security_text(request: dict) -> str:
        """Security checks task_description for injection / adversarial content."""
        return request.get("task_description") or ""

    @staticmethod
    def get_fairness_text(request: dict) -> str:
        """
        Fairness checks task_description for biased *instructions*.
        NOT the output — bias in a prompt is an intent-level violation.
        """
        return request.get("task_description") or ""

    @staticmethod
    def get_compliance_text(request: dict) -> str:
        """Compliance checks task_description for illegal / regulatory-violating intent."""
        return request.get("task_description") or ""

    @staticmethod
    def get_privacy_text(request: dict) -> str:
        """Privacy scans task_description for PII in the *input*."""
        return request.get("task_description") or ""

    # ── CP2 text ──────────────────────────────────────────────────────────────

    @staticmethod
    def get_cp2_text(output: str, original_request: dict | None = None) -> str:
        """
        Text CP2 should evaluate — the raw agent output.
        The original_request is available for scope-comparison checks.
        """
        return output or ""

    @staticmethod
    def get_output_privacy_text(output: str) -> str:
        """Privacy pillar at CP2 scans the agent output for PII."""
        return output or ""

    @staticmethod
    def get_output_compliance_text(output: str) -> str:
        """Compliance pillar at CP2 checks output for regulatory violations."""
        return output or ""

    @staticmethod
    def get_output_security_text(output: str) -> str:
        """Security pillar at CP2 checks output for injection artefacts."""
        return output or ""
