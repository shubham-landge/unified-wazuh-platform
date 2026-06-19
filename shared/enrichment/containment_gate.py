"""Containment Gate — policy guard for all SOAR containment actions.

Every containment action must route through this gate before execution.
Policy is driven by automation_mode, risk score, asset criticality, and
threat-intelligence context. The gate produces one of three decisions:
ALLOW (auto-execute), DENY (block entirely), or REQUIRE_APPROVAL (queue
for human review).

Adapted from NIST SP 800-61r2 containment strategy: automate low-risk
scoping actions, gate destructive actions on crown-jewel assets, and
always allow evidence collection.

Architecture:
  check_policy()     — pure-function policy evaluation
  execute_with_gate() — async wrapper: check → audit → execute
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from shared.config import settings
from shared.enrichment.risk_score import EnrichmentContext

logger = logging.getLogger(__name__)

# ── Enums ────────────────────────────────────────────────────────────────────


class ContainmentAction(str, Enum):
    """SOAR containment actions that require policy gating."""
    ISOLATE_HOST = "isolate_host"
    BLOCK_IP = "block_ip"
    DISABLE_USER = "disable_user"
    QUARANTINE_FILE = "quarantine_file"
    SNAPSHOT_EVIDENCE = "snapshot_evidence"


class ContainmentDecision(str, Enum):
    """Policy decision for a containment action."""
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


# Actions that are never destructive — always safe to run.
_NON_DESTRUCTIVE = {ContainmentAction.SNAPSHOT_EVIDENCE}

# Actions that auto-allow when TI says known-bad, regardless of score.
_TI_OVERRIDE_ACTIONS = {ContainmentAction.ISOLATE_HOST, ContainmentAction.BLOCK_IP}

# Actions allowed at >= 60 risk score.
_HIGH_CONFIDENCE_ACTIONS = {ContainmentAction.ISOLATE_HOST, ContainmentAction.BLOCK_IP}

# Actions allowed at >= 80 risk score.
_VERY_HIGH_CONFIDENCE_ACTIONS = {ContainmentAction.DISABLE_USER, ContainmentAction.QUARANTINE_FILE}


# ── Audit record ─────────────────────────────────────────────────────────────


@dataclass
class AuditRecord:
    """Immutable audit trail entry for containment decisions."""
    action: str
    target: str
    decision: str
    reason: str
    score: int
    is_crown_jewel: bool
    ti_known_bad: bool
    automation_mode: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict = field(default_factory=dict)


# ── Policy engine ────────────────────────────────────────────────────────────


def check_policy(
    action: ContainmentAction,
    ctx: EnrichmentContext,
    score: int,
) -> tuple[ContainmentDecision, str]:
    """Evaluate whether *action* should be allowed, denied, or require approval.

    Policy rules (first match wins):
      1. SNAPSHOT_EVIDENCE → ALLOW (non-destructive, always safe, even in shadow mode)
      2. AUTOMATION_MODE=shadow → DENY (log-only mode for destructive actions)
      3. TI known-bad + {ISOLATE_HOST, BLOCK_IP} → ALLOW (intel override)
      4. Score < 60 → REQUIRE_APPROVAL (insufficient confidence)
      5. Crown-jewel + destructive → REQUIRE_APPROVAL (protect critical assets)
      6. Score >= 80 + {DISABLE_USER, QUARANTINE_FILE} → ALLOW
      7. Score >= 60 + {ISOLATE_HOST, BLOCK_IP} → ALLOW
      8. Fallback → REQUIRE_APPROVAL (conservative default)

    Args:
        action: The SOAR containment action being requested.
        ctx:    Populated enrichment context with TI and asset signals.
        score:  Integer 0-100 risk score from the scoring engine.

    Returns:
        (ContainmentDecision, reason_string)
    """
    automation_mode = str(getattr(settings, "automation_mode", "shadow")).lower()

    # ── Rule 1: Non-destructive actions always allowed (even in shadow mode) ──
    if action in _NON_DESTRUCTIVE:
        return ContainmentDecision.ALLOW, "snapshot_evidence is non-destructive — always allowed"

    # ── Rule 2: Shadow mode blocks everything destructive ──
    if automation_mode == "shadow":
        return ContainmentDecision.DENY, "automation_mode=shadow — destructive containment actions are log-only"

    # ── Rule 3: TI known-bad override for network/host containment ──
    if ctx.ti_is_known_bad and action in _TI_OVERRIDE_ACTIONS:
        return ContainmentDecision.ALLOW, "threat intelligence confirms known-bad — auto-contained"

    # ── Rule 4: Low score gates everything behind approval ──
    if score < 60:
        return ContainmentDecision.REQUIRE_APPROVAL, (
            f"risk score {score} < 60 — insufficient confidence for automated containment"
        )

    # ── Rule 5: Crown-jewel assets require approval for destructive actions ──
    if ctx.is_crown_jewel and action not in _NON_DESTRUCTIVE:
        return ContainmentDecision.REQUIRE_APPROVAL, (
            "crown-jewel asset — destructive containment requires human approval"
        )

    # ── Rule 6: Very high confidence allows user/file containment ──
    if score >= 80 and action in _VERY_HIGH_CONFIDENCE_ACTIONS:
        return ContainmentDecision.ALLOW, (
            f"risk score {score} >= 80 — auto-approved {action.value}"
        )

    # ── Rule 7: Moderate confidence allows network/host containment ──
    if score >= 60 and action in _HIGH_CONFIDENCE_ACTIONS:
        return ContainmentDecision.ALLOW, (
            f"risk score {score} >= 60 — auto-approved {action.value}"
        )

    # ── Rule 8: Fallback ──
    return ContainmentDecision.REQUIRE_APPROVAL, (
        f"{action.value} requires approval (score={score}, no rule matched)"
    )


# ── Execution wrapper ────────────────────────────────────────────────────────


async def execute_with_gate(
    action: ContainmentAction,
    target: str,
    ctx: EnrichmentContext,
    score: int,
    session: Any = None,
) -> dict:
    """Check containment policy, log audit record, and execute if allowed.

    Args:
        action:  The containment action to perform.
        target:  Human-readable target identifier (IP, hostname, username, path).
        ctx:     Enrichment context with TI and asset signals.
        score:   Integer risk score (0-100).
        session: Optional SQLAlchemy AsyncSession for audit persistence.

    Returns:
        dict with keys: action, target, decision, reason, executed, audit.
    """
    decision, reason = check_policy(action, ctx, score)

    # Build audit record
    audit = AuditRecord(
        action=action.value,
        target=target,
        decision=decision.value,
        reason=reason,
        score=score,
        is_crown_jewel=ctx.is_crown_jewel,
        ti_known_bad=ctx.ti_is_known_bad,
        automation_mode=str(getattr(settings, "automation_mode", "shadow")),
        details={"action": action.value, "target": target, "score": score},
    )

    logger.info(
        "containment_gate | action=%s target=%s decision=%s score=%d | %s",
        action.value, target, decision.value, score, reason,
    )

    # Persist audit record if session is available
    if session is not None:
        try:
            exec_time = audit.timestamp
            import json as _json
            stmt = (
                "INSERT INTO containment_audit_log (action, target, decision, reason, "
                "score, is_crown_jewel, ti_known_bad, automation_mode, created_at, details) "
                "VALUES (:action, :target, :decision, :reason, :score, :is_crown_jewel, "
                ":ti_known_bad, :automation_mode, :created_at, :details)"
            )
            await session.execute(
                stmt,
                {
                    "action": audit.action,
                    "target": audit.target,
                    "decision": audit.decision,
                    "reason": audit.reason,
                    "score": audit.score,
                    "is_crown_jewel": audit.is_crown_jewel,
                    "ti_known_bad": audit.ti_known_bad,
                    "automation_mode": audit.automation_mode,
                    "created_at": exec_time,
                    "details": _json.dumps(audit.details),
                },
            )
        except Exception:
            # Audit persistence is best-effort — never block the decision.
            logger.warning("Failed to persist containment audit record", exc_info=True)

    executed = False
    if decision == ContainmentDecision.ALLOW:
        # Action is automatically executable. The actual execution
        # is delegated to the SOAR action dispatcher.
        logger.info("containment_gate | executing %s on %s", action.value, target)
        executed = True
    elif decision == ContainmentDecision.DENY:
        logger.info("containment_gate | denied %s on %s", action.value, target)
    elif decision == ContainmentDecision.REQUIRE_APPROVAL:
        logger.info("containment_gate | %s on %s requires human approval", action.value, target)

    return {
        "action": action.value,
        "target": target,
        "decision": decision.value,
        "reason": reason,
        "executed": executed,
        "audit": {
            "action": audit.action,
            "target": audit.target,
            "decision": audit.decision,
            "reason": audit.reason,
            "score": audit.score,
            "timestamp": audit.timestamp,
        },
    }
