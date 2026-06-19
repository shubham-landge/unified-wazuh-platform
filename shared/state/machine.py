"""Alert, incident, and kill-chain state machines with explicit transitions, guards, and audit.

Each machine defines its allowed transitions in a dict[State, set[State]].
The ``transition()`` function checks the map, runs an optional guard, and
emits a ``TransitionAudit`` dataclass via an ``audit_sink`` callback
(compatible with the ``CaseEvent`` model fields).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ── Enums ────────────────────────────────────────────────────────────────────


class AlertState(str, Enum):
    """Alert triage lifecycle states."""

    NEW = "new"
    ENRICHED = "enriched"
    TRIAGED = "triaged"
    AUTO_CLOSED = "auto_closed"
    ESCALATED = "escalated"
    SUPPRESSED = "suppressed"


class IncidentState(str, Enum):
    """Incident response lifecycle states."""

    OPEN = "open"
    ADVANCING = "advancing"
    CONTAINED = "contained"
    CLOSED = "closed"


class KillChainStage(str, Enum):
    """Lockheed Martin Cyber Kill Chain stages (S0 alignment)."""

    RECON = "recon"
    WEAPONIZE = "weaponize"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    C2 = "c2"
    ACTIONS_ON_OBJECTIVE = "actions_on_objective"


# ── Allowed transitions ─────────────────────────────────────────────────────

# Alert: new → enriched → triaged → {auto_closed | escalated | suppressed}
ALERT_TRANSITIONS: dict[AlertState, set[AlertState]] = {
    AlertState.NEW: {AlertState.ENRICHED},
    AlertState.ENRICHED: {AlertState.TRIAGED},
    AlertState.TRIAGED: {AlertState.AUTO_CLOSED, AlertState.ESCALATED, AlertState.SUPPRESSED},
    AlertState.AUTO_CLOSED: set(),
    AlertState.ESCALATED: set(),
    AlertState.SUPPRESSED: set(),
}

# Incident: open → advancing → contained → closed
INCIDENT_TRANSITIONS: dict[IncidentState, set[IncidentState]] = {
    IncidentState.OPEN: {IncidentState.ADVANCING, IncidentState.CLOSED},
    IncidentState.ADVANCING: {IncidentState.CONTAINED, IncidentState.CLOSED},
    IncidentState.CONTAINED: {IncidentState.CLOSED},
    IncidentState.CLOSED: set(),
}

# Kill chain — ordered stages for directional advancement.
KILLCHAIN_STAGES: list[KillChainStage] = [
    KillChainStage.RECON,
    KillChainStage.WEAPONIZE,
    KillChainStage.DELIVERY,
    KillChainStage.EXPLOITATION,
    KillChainStage.INSTALLATION,
    KillChainStage.C2,
    KillChainStage.ACTIONS_ON_OBJECTIVE,
]

# Build kill-chain transitions: can stay on the same stage or advance forward,
# but never regress to an earlier stage.
KILLCHAIN_TRANSITIONS: dict[KillChainStage, set[KillChainStage]] = {}
for i, stage in enumerate(KILLCHAIN_STAGES):
    KILLCHAIN_TRANSITIONS[stage] = {KILLCHAIN_STAGES[j] for j in range(i, len(KILLCHAIN_STAGES))}

# Combined lookup so `transition()` can resolve any state type without
# the caller needing to pick the right map.
allowed_transitions: dict[Enum, set[Enum]] = {}
for _d in (ALERT_TRANSITIONS, INCIDENT_TRANSITIONS, KILLCHAIN_TRANSITIONS):
    allowed_transitions.update(_d)


# ── Audit dataclass ──────────────────────────────────────────────────────────


@dataclass
class TransitionAudit:
    """Data produced by a successful transition.

    Fields mirror ``CaseEvent`` columns so the caller can persist the audit
    row without the state machine knowing about SQLAlchemy.
    """

    event_type: str = "state_changed"
    old_value: str = ""
    new_value: str = ""
    description: str = ""
    event_meta: dict | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Type aliases
State = Enum
GuardFn = Callable[[State, State, dict | None], bool]
AuditSink = Callable[[TransitionAudit], Any]


# ── Transition function ─────────────────────────────────────────────────────


def transition(
    current: State,
    next: State,
    guard_fn: GuardFn | None = None,
    audit_ctx: dict | None = None,
    *,
    allowed: dict[State, set[State]] | None = None,
    audit_sink: AuditSink | None = None,
) -> bool:
    """Attempt a state transition.

    Args:
        current: Current state enum member.
        next: Target state enum member.
        guard_fn: Optional ``(current, next, audit_ctx) -> bool``.
            When provided and returns ``False`` the transition is blocked.
        audit_ctx: Optional dict merged into ``event_meta``.
        allowed: Transition map override (defaults to ``allowed_transitions``).
        audit_sink: Optional callable receiving a ``TransitionAudit`` on success.

    Returns:
        ``True`` if the transition was allowed and passed the guard.
    """
    if allowed is None:
        allowed = allowed_transitions

    trans_map = allowed.get(current)
    if trans_map is None or next not in trans_map:
        logger.warning("Transition blocked: %s -> %s (not in allowed set)", current, next)
        return False

    if guard_fn is not None and not guard_fn(current, next, audit_ctx):
        logger.info("Transition blocked by guard: %s -> %s", current, next)
        return False

    audit = TransitionAudit(
        old_value=current.value if isinstance(current, Enum) else str(current),
        new_value=next.value if isinstance(next, Enum) else str(next),
        description=f"State transition: {current} -> {next}",
        event_meta=audit_ctx.copy() if audit_ctx else None,
    )

    if audit_sink is not None:
        audit_sink(audit)

    logger.info("Transition: %s -> %s", current, next)
    return True
