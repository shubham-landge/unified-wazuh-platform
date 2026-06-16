"""Noise-reduction pre-triage stage.

Implements the briefing's Use Case 2 ("keep / drop / downgrade") as a
*deterministic* gate that runs BEFORE the LLM. On a CPU-only deployment this is
what makes level >= 7 triage feasible at ~2,000-source scale: it collapses
duplicate bursts (via the existing correlation/incident grouping) and drops
known-noise rule classes so the 3B model only sees unique, worth-triaging
incidents.

Decision order (cheapest checks first, no LLM, no network):
  1. below triage threshold (rule_level < triage_min_level)      -> DROP
  2. rule id / group on the drop list                            -> DROP
  3. duplicate beyond suppress threshold in the same incident    -> DROP
  4. rule id on the downgrade list                               -> DOWNGRADE
  5. otherwise                                                    -> KEEP

DROP      = do not call the LLM; alert stays in Wazuh, attached to its incident.
DOWNGRADE = triage on the fast (3B) tier only, never escalate to the 7B tier.
KEEP      = normal tiered triage.
"""
import logging
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from shared.config import settings
from shared.models.alert import Alert
from shared.models.alert_dedup import AlertIncident
from shared.alert_dedup import dedup_alert_before_triage

logger = logging.getLogger(__name__)

KEEP = "keep"
DOWNGRADE = "downgrade"
DROP = "drop"


@dataclass
class NoiseDecision:
    """Outcome of the pre-triage gate for a single alert."""

    action: str  # KEEP | DOWNGRADE | DROP
    reason: str
    incident: AlertIncident | None = None
    force_fast_tier: bool = False

    @property
    def should_triage(self) -> bool:
        return self.action != DROP


def _csv_ints(raw: str) -> set[int]:
    out: set[int] = set()
    for part in (raw or "").split(","):
        part = part.strip()
        if part:
            try:
                out.add(int(part))
            except ValueError:
                logger.warning("noise_reduction: ignoring non-int rule id %r", part)
    return out


def _csv_strs(raw: str) -> list[str]:
    return [p.strip().lower() for p in (raw or "").split(",") if p.strip()]


def _matches_drop_group(alert: Alert, drop_groups: list[str]) -> str | None:
    if not drop_groups:
        return None
    groups = [str(g).lower() for g in (alert.rule_groups or [])]
    for needle in drop_groups:
        for g in groups:
            if needle in g:
                return needle
    return None


async def evaluate(
    session: AsyncSession,
    alert: Alert,
    tenant_id: str | None,
) -> NoiseDecision:
    """Decide whether/how to triage an alert. Always returns a decision.

    Side effect: ensures the alert is attached to its correlation incident
    (creating/updating it via the existing dedup path), so duplicate bursts
    are tracked even when triage is suppressed. The caller is responsible for
    committing the session.
    """
    if not settings.noise_reduction_enabled:
        return NoiseDecision(action=KEEP, reason="noise_reduction_disabled")

    level = alert.rule_level or 0

    # 1. Below the AI-triage threshold — stays in Wazuh, no LLM.
    if level < settings.triage_min_level:
        return NoiseDecision(
            action=DROP,
            reason=f"below_min_level (level={level} < {settings.triage_min_level})",
        )

    # 2. Explicit drop lists (rule id or noisy group).
    drop_ids = _csv_ints(settings.noise_drop_rule_ids)
    if alert.rule_id is not None and alert.rule_id in drop_ids:
        return NoiseDecision(action=DROP, reason=f"drop_rule_id ({alert.rule_id})")

    matched_group = _matches_drop_group(alert, _csv_strs(settings.noise_drop_rule_groups))
    if matched_group:
        return NoiseDecision(action=DROP, reason=f"drop_rule_group ({matched_group})")

    # 3. Deduplicate / correlate. Attaches the alert to an incident group and
    #    increments its count. Bursts beyond the suppress threshold are dropped.
    incident = await dedup_alert_before_triage(session, alert, tenant_id)
    if (
        settings.alert_dedup_enabled
        and incident.alert_count > settings.noise_dedup_suppress_after
    ):
        return NoiseDecision(
            action=DROP,
            reason=(
                f"dedup_suppressed (incident={incident.id}, "
                f"count={incident.alert_count} > {settings.noise_dedup_suppress_after})"
            ),
            incident=incident,
        )

    # 4. Downgrade list — triage, but pin to the fast tier (never escalate to 7B).
    downgrade_ids = _csv_ints(settings.noise_downgrade_rule_ids)
    if alert.rule_id is not None and alert.rule_id in downgrade_ids:
        return NoiseDecision(
            action=DOWNGRADE,
            reason=f"downgrade_rule_id ({alert.rule_id})",
            incident=incident,
            force_fast_tier=True,
        )

    # 5. Keep — normal tiered triage.
    return NoiseDecision(action=KEEP, reason="kept", incident=incident)
