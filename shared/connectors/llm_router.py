import logging
from shared.config import settings
from shared.connectors.llm_provider import LLMProvider, OllamaProvider, get_provider

logger = logging.getLogger(__name__)


def _get_complex_techniques() -> set[str]:
    raw = settings.llm_tier_complex_techniques
    return set(t.strip() for t in raw.split(",") if t.strip())


def _get_known_bad_ips() -> set[str]:
    raw = settings.llm_tier_known_bad_ips
    return set(t.strip() for t in raw.split(",") if t.strip())

def rule_historical_accuracy(rule_id: int | None) -> float | None:
    if rule_id is None:
        return None
    return None


def asset_criticality(agent_id: str | None) -> int:
    return 0


def is_burst_alert(alert) -> bool:
    if alert.rule_firedtimes and alert.rule_firedtimes > 5:
        return True
    from shared.config import settings
    window = getattr(settings, 'llm_tier_burst_window_minutes', 10)
    if hasattr(alert, 'created_at') and alert.created_at:
        from datetime import datetime, timezone, timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        ts = alert.created_at
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts >= cutoff and (alert.rule_firedtimes or 0) > 3:
            return True
    return False


def tenant_tier(tenant_id: str | None) -> str:
    return "standard"


async def user_feedback_negative_rate(rule_id: int | None, db_session=None) -> float:
    if db_session is None or rule_id is None:
        return 0.0
    try:
        async with db_session.begin_nested():
            from shared.models.feedback import UserFeedback
            from shared.models.ai_triage_result import AiTriageResult
            from sqlalchemy import select, func

            total = await db_session.execute(
                select(func.count(UserFeedback.id))
                .join(AiTriageResult, UserFeedback.triage_result_id == AiTriageResult.id)
                .where(AiTriageResult.category == str(rule_id))
            )
            negative = await db_session.execute(
                select(func.count(UserFeedback.id))
                .join(AiTriageResult, UserFeedback.triage_result_id == AiTriageResult.id)
                .where(AiTriageResult.category == str(rule_id), UserFeedback.rating <= 2)
            )
            total_count = total.scalar() or 0
            if total_count == 0:
                return 0.0
            return (negative.scalar() or 0) / total_count
    except Exception as e:
        logger.warning("Failed to compute user_feedback_negative_rate: %s", e)
        return 0.0


class TieredRouter:
    async def get_provider(self, alert=None, tenant_id: str | None = None, db_session=None,
                           force_fast: bool = False, force_escalation: bool = False) -> LLMProvider:
        strategy = settings.llm_tier_strategy

        # Cross-domain / advancing incidents can demand the cloud escalation tier
        # directly, bypassing the per-alert score (incident-level reasoning).
        if force_escalation and self._escalation_enabled():
            logger.info("Routing to ESCALATION tier (forced, cross-domain)")
            return self._build_escalation_provider()

        # Noise-reduction downgrade pins the alert to the fast tier, bypassing
        # the score so it can never escalate to the (slower, CPU-costly) 7B tier.
        if force_fast:
            return self._build_fast_provider()

        if strategy == "fast":
            return self._build_fast_provider()
        if strategy == "full":
            return self._build_full_provider()

        score = await self._compute_score(alert, tenant_id, db_session)
        logger.debug("TieredRouter score=%d for alert %s", score, getattr(alert, "id", None))

        # Escalation is opt-in and only for the hardest cases, so local CPU tiers
        # stay the always-on baseline and cloud spend is bounded.
        if self._escalation_enabled() and score >= settings.llm_tier_escalation_score_threshold:
            logger.info("Routing to ESCALATION tier (score=%d)", score)
            return self._build_escalation_provider()

        if score >= settings.llm_tier_score_threshold:
            logger.info("Routing to FULL tier (score=%d)", score)
            return self._build_full_provider()

        logger.debug("Routing to FAST tier (score=%d)", score)
        return self._build_fast_provider()

    @staticmethod
    def _escalation_enabled() -> bool:
        return bool(getattr(settings, "llm_tier_escalation_enabled", False))

    async def _compute_score(self, alert, tenant_id: str | None, db_session=None) -> int:
        score = 0

        if alert is None:
            return score

        if alert.rule_level is not None and alert.rule_level >= settings.llm_tier_level_threshold:
            score += 3

        if alert.source_ip:
            known_bad = _get_known_bad_ips()
            if alert.source_ip in known_bad:
                score += 2

        if asset_criticality(alert.agent_id) >= 4:
            score += 2

        hist_acc = rule_historical_accuracy(alert.rule_id)
        if hist_acc is not None and hist_acc < 0.7:
            score += 2

        if alert.mitre_technique:
            complex_techs = _get_complex_techniques()
            if alert.mitre_technique in complex_techs:
                score += 1

        if is_burst_alert(alert):
            score -= 2

        if tenant_tier(tenant_id) == "premium":
            score += 2

        neg_rate = await user_feedback_negative_rate(alert.rule_id, db_session=db_session)
        if neg_rate > 0.3:
            score += 2

        return score

    def _build_fast_provider(self) -> LLMProvider:
        prov = settings.llm_tier_fast_provider
        model = settings.llm_tier_fast_model
        return self._resolve_provider(prov, model)

    def _build_full_provider(self) -> LLMProvider:
        prov = settings.llm_tier_full_provider
        model = settings.llm_tier_full_model
        return self._resolve_provider(prov, model)

    def _build_escalation_provider(self) -> LLMProvider:
        prov = getattr(settings, "llm_tier_escalation_provider", "gemini")
        model = getattr(settings, "llm_tier_escalation_model", "gemini-2.5-flash")
        return self._resolve_provider(prov, model)

    def _resolve_provider(self, provider_name: str, model: str | None = None) -> LLMProvider:
        # build_provider applies the per-tier model override to every provider,
        # so the cloud escalation tier actually uses its configured model.
        from shared.connectors.llm_provider import build_provider
        return build_provider(provider_name, model)
