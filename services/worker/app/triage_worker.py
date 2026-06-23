import asyncio
import json
import logging
import uuid
from pathlib import Path
import redis.asyncio as redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings
from shared.models.alert import Alert
from shared.models.ai_triage_result import AiTriageResult
from shared.models.case import Case
from shared.models.case_event import CaseEvent
from shared.models.case_investigation_step import CaseInvestigationStep
from shared.connectors.circuit_breaker import CircuitBreaker, CircuitBreakerOpenError
from shared.connectors.llm_provider import get_provider
from shared.connectors.llm_router import TieredRouter
from shared import noise_reduction
from shared import triage_cache  # kept for backward-compat import (tests patch this)
from shared import triage_rag
from shared.enrichment.pipeline import enrich_alert
from shared.enrichment.risk_score import compute_risk_score
from shared.enrichment.decision import decide, DecisionLevel
from shared.enrichment.auto_close import should_auto_close, execute_auto_close
from shared.enrichment.semantic_cache import SemanticCache
from shared.enrichment.decision_fusion import fuse_verdict
from shared.models.triage import validate_triage_output
from shared.metrics import record_triage_success, record_triage_fail, record_triage_latency

logger = logging.getLogger(__name__)

_PROMPTS_DIR = Path(__file__).parent.parent.parent.parent / "services" / "api" / "app" / "prompts"

def _load_system_prompt() -> str:
    path = _PROMPTS_DIR / "system_soc_triage.md"
    try:
        text = path.read_text()
        # Strip the comment header lines (lines starting with #)
        lines = [l for l in text.splitlines() if not l.startswith("#")]
        return "\n".join(lines).strip()
    except FileNotFoundError:
        logger.warning("system_soc_triage.md not found, using inline fallback")
        return (
            "You are a defensive SOC triage copilot for Wazuh. "
            "Analyze the alert and return structured JSON only. "
            "Never recommend destructive actions."
        )

TRIAGE_PROMPT_SYSTEM = _load_system_prompt()

# Fail pending triage rows older than this many seconds if the worker dies or
# the LLM never returns.
_PENDING_REAPER_TIMEOUT_SECONDS = 600


class TriageWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None
        self._shutdown = False
        self._concurrency = max(1, getattr(settings, 'worker_triage_concurrency', 1))
        # Circuit breaker for the background reaper: protect against cascading
        # DB write failures by opening after N consecutive _reap_stale_pending
        # failures and skipping reaper cycles until the recovery window expires.
        self._reaper_breaker = CircuitBreaker(
            name="triage_reaper",
            failure_threshold=getattr(settings, "reaper_cb_failure_threshold", 3),
            recovery_timeout=getattr(settings, "reaper_cb_recovery_timeout", 300.0),
        )

    @staticmethod
    def _is_shadow_mode() -> bool:
        """Return True when automation_mode is 'shadow' → log decisions, no action."""
        return str(getattr(settings, 'automation_mode', 'shadow')).lower() == 'shadow'

    async def start(self):
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info(
            "Triage worker started with %d consumer(s). Waiting for alerts...",
            self._concurrency,
        )

        # Launch N parallel queue-loop consumers + 1 reaper loop.
        consumers = [
            self._run_queue_loop(idx) for idx in range(self._concurrency)
        ]
        await asyncio.gather(
            *consumers,
            self._run_reaper_loop(),
        )

    async def _run_queue_loop(self, consumer_idx: int = 0):
        while not self._shutdown:
            try:
                item = await self.redis_client.brpop("triage_queue", timeout=5)
                if item:
                    _, msg = item
                    await self.process_message(json.loads(msg))
            except TypeError:
                continue
            except Exception as e:
                logger.error(
                    "Triage worker[%d] error: %s", consumer_idx, e, exc_info=True
                )
                await asyncio.sleep(1)

    async def _run_reaper_loop(self):
        """Periodically fail triage rows stuck in 'pending' too long.

        Runs independently of the dashboard poll — no API call required.
        """
        while not self._shutdown:
            try:
                await asyncio.sleep(60)
                await self._reap_stale_pending()
            except asyncio.CancelledError:
                break
            except CircuitBreakerOpenError:
                # Circuit is open; the reaper is backing off. Log at debug level
                # to avoid noise — _reap_stale_pending already logged the skip.
                logger.debug("Reaper circuit open; back-off cycle")
            except Exception as exc:
                logger.error("Reaper loop error: %s", exc)

    async def _reap_stale_pending(self):
        """Fail triage rows stuck in 'pending' too long.

        Wraps the DB write in a CircuitBreaker so that persistent DB failures
        open the circuit and skip reaper cycles until the recovery window expires.
        """
        try:
            await self._reaper_breaker.call(self._execute_reaper_update)
        except CircuitBreakerOpenError:
            logger.debug("Reaper circuit open; skipping this cycle")
            return

    async def _execute_reaper_update(self):
        """Perform the DB update to fail stale pending triage rows.

        Extracted as a callable target for the CircuitBreaker so that only
        DB write failures are counted, not transient errors in the reaper loop.
        """
        from datetime import datetime, timedelta, timezone
        from sqlalchemy import update
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=_PENDING_REAPER_TIMEOUT_SECONDS)
        async with self.session_factory() as session:
            stmt = (
                update(AiTriageResult)
                .where(
                    AiTriageResult.status == "pending",
                    AiTriageResult.created_at < cutoff,
                )
                .values(
                    status="failed",
                    success=False,
                    error_message="Reaper: triage timed out",
                )
            )
            result = await session.execute(stmt)
            await session.commit()
            if result.rowcount:
                logger.warning("Reaper failed %d stale pending triage row(s)", result.rowcount)

    async def process_message(self, msg: dict):
        alert_id = msg.get("alert_id")
        if not alert_id:
            return

        # Manual "Analyze" requests carry a pre-created pending row + force_fast.
        manual = bool(msg.get("manual", False))
        triage_id = msg.get("triage_id")
        force_fast_req = bool(msg.get("force_fast", False))

        logger.info("Processing triage for alert %s%s", alert_id, " (manual)" if manual else "")

        try:
            async with self.session_factory() as session:
                result = await session.execute(select(Alert).where(Alert.id == alert_id))
                alert = result.scalar_one_or_none()
                if not alert:
                    logger.warning("Alert %s not found", alert_id)
                    await self._mark_manual_failed(triage_id, "Alert not found")
                    return

                if manual:
                    # Analyst explicitly asked for analysis: skip the noise gate
                    # entirely and honour the requested tier.
                    force_fast = force_fast_req
                    incident = None
                else:
                    # ── Noise-reduction pre-triage gate (keep/drop/downgrade) ──
                    # Runs before the LLM to protect the CPU triage budget.
                    decision = await noise_reduction.evaluate(
                        session, alert, str(alert.tenant_id) if alert.tenant_id else None
                    )
                    incident = decision.incident
                    if not decision.should_triage:
                        await session.commit()  # persist incident attachment / counts
                        logger.info(
                            "Triage suppressed for alert %s: %s", alert_id, decision.reason
                        )
                        if self.redis_client:
                            await self.redis_client.incr("triage_suppressed_total")
                        return
                    if decision.action == noise_reduction.DOWNGRADE:
                        logger.info("Alert %s downgraded to fast tier: %s", alert_id, decision.reason)
                    force_fast = decision.force_fast_tier

                # ── Pre-LLM enrichment, risk scoring, and decision (S0) ──
                ctx = await enrich_alert(alert, str(alert.tenant_id), session, self.redis_client)
                score = compute_risk_score(ctx)
                decision_result = decide(ctx, score, alert.rule_level)
                logger.info(
                    "Enrichment decision for alert %s: score=%d level=%s (%s)",
                    alert_id,
                    score,
                    decision_result.level.name,
                    decision_result.reason,
                )

                # ── Decision gate routing ──
                # Skip L0/L1 suppression when the analyst explicitly requested
                # triage via the "Analyze" button (manual + force_fast).
                skip_gate = manual and force_fast_req
                if not skip_gate:
                    if decision_result.level == DecisionLevel.L0_SUPPRESS:
                        logger.info("L0 suppress: alert %s", alert_id)
                        if self._is_shadow_mode():
                            logger.info(
                                "[SHADOW] would suppress alert %s: %s (score=%d)",
                                alert_id, decision_result.reason, score,
                            )
                        else:
                            alert.status = "suppressed"
                            await session.commit()
                        return

                    if decision_result.level == DecisionLevel.L1_AUTO_CLOSE:
                        eligible, reason = should_auto_close(ctx, score, alert.rule_level)
                        if eligible and settings.auto_close_enabled:
                            await execute_auto_close(
                                session, str(alert_id), str(alert.tenant_id),
                                reason, score, ctx,
                            )
                            return

                # L3/L4: deterministic verdict, fast tier for narrative only
                l3_l4_deterministic = decision_result.level in (
                    DecisionLevel.L3_ESCALATE, DecisionLevel.L4_CRITICAL
                )
                if l3_l4_deterministic:
                    force_fast = True

                # Build enrichment context for the LLM prompt
                enrichment_context = ""
                parts = []
                if ctx.ti_confidence > 0 or ctx.ti_is_known_bad:
                    ti_parts = [f"confidence={ctx.ti_confidence:.2f}"]
                    if ctx.ti_is_kev:
                        ti_parts.append("KEV")
                    if ctx.ti_is_known_bad:
                        ti_parts.append("known bad")
                    parts.append("Threat Intel: " + ", ".join(ti_parts))
                if ctx.ueba_zscore > 0:
                    parts.append(f"UEBA: z-score={ctx.ueba_zscore:.2f}")
                if ctx.geo_tor_vpn or ctx.geo_bad_asn or ctx.geo_impossible_travel:
                    geo_parts = []
                    if ctx.geo_impossible_travel:
                        geo_parts.append("impossible travel")
                    if ctx.geo_tor_vpn:
                        geo_parts.append("Tor/VPN")
                    if ctx.geo_bad_asn:
                        geo_parts.append("bad ASN")
                    parts.append("GeoIP: " + ", ".join(geo_parts))
                if ctx.vuln_matched:
                    vuln_parts = [f"EPSS={ctx.vuln_epss:.3f}"]
                    if ctx.vuln_is_kev:
                        vuln_parts.append("KEV")
                    parts.append("Vulnerabilities: " + ", ".join(vuln_parts))
                if ctx.is_allowlisted or ctx.ti_is_known_bad:
                    if ctx.is_allowlisted:
                        parts.append("Watchlist: allowlisted")
                    elif ctx.ti_is_known_bad:
                        parts.append("Watchlist: blocklisted")
                if parts:
                    enrichment_context = "Enrichment:\n" + "\n".join("- " + p for p in parts) + "\n"

                provider = await TieredRouter().get_provider(
                    alert=alert,
                    tenant_id=str(alert.tenant_id),
                    db_session=session,
                    force_fast=force_fast,
                )
                tier = "full" if provider.name().startswith(("openai", "gemini", "claude")) or "7b" in provider.name() else "fast"
                logger.info("Triaging alert %s with %s (%s tier)", alert_id, provider.name(), tier)

                user_prompt = (
                    f"Alert Rule: {alert.rule_description}\n"
                    f"Rule ID: {alert.rule_id}\n"
                    f"Level: {alert.rule_level}\n"
                    f"Groups: {alert.rule_groups}\n"
                    f"Agent: {alert.agent_name} ({alert.agent_ip})\n"
                    f"Source IP: {alert.source_ip}\n"
                    f"User: {alert.user_name}\n"
                    f"Process: {alert.process_name}\n"
                    f"MITRE: {alert.mitre_tactic} / {alert.mitre_technique}\n"
                    f"{enrichment_context}"
                )

                # ── Semantic result cache (L2 only: skip LLM for near-duplicates) ──
                semantic_cache_obj: SemanticCache | None = None
                alert_features: dict | None = None
                cache_hit = False

                if decision_result.level == DecisionLevel.L2_TRIAGE:
                    tenant_id = str(alert.tenant_id) if alert.tenant_id else "default"
                    semantic_cache_obj = SemanticCache(
                        redis_client=self.redis_client,
                        tenant_id=tenant_id,
                    )
                    alert_features = {
                        "rule_id": str(alert.rule_id) if alert.rule_id else "",
                        "rule_description": alert.rule_description or "",
                        "source_ip": alert.source_ip or "",
                        "mitre_technique": alert.mitre_technique or "",
                        "rule_groups": alert.rule_groups or "",
                    }
                    hit, cached_data = await semantic_cache_obj.lookup(
                        alert_features,
                        threshold=settings.triage_cache_similarity_threshold,
                    )
                    if hit:
                        logger.info("Semantic cache hit for alert %s", alert_id)
                        cache_hit = True
                        result_data = cached_data
                        result_data["_cached"] = True
                        result_data["_cache_source"] = "semantic"

                if not cache_hit:
                    # ── RAG augmentation: retrieve similar past verdicts ──
                    rag_context = await triage_rag.build_triage_context(
                        session, alert, k=3, tenant_id=str(alert.tenant_id) if alert.tenant_id else None
                    )
                    system_prompt = TRIAGE_PROMPT_SYSTEM + rag_context if rag_context else TRIAGE_PROMPT_SYSTEM

                    result_data = await provider.analyze(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                    )

                # ── Hybrid decision fusion (L2 only; L3/L4 are deterministic) ──
                if not cache_hit and decision_result.level in (
                    DecisionLevel.L2_TRIAGE,
                ):
                    result_data = fuse_verdict(result_data, ctx, score)
                    logger.debug(
                        "Fusion applied=%s overrides=%s for alert %s",
                        result_data.get("fusion_applied"),
                        result_data.get("fusion_overrides"),
                        alert_id,
                    )

                # ── L3/L4 deterministic override: verdict pre-determined, LLM for narrative only ──
                if l3_l4_deterministic:
                    if self._is_shadow_mode():
                        logger.info(
                            "[SHADOW] L3/L4 deterministic override suppressed for alert %s: "
                            "would set verdict=%s severity=%s (score=%d)",
                            alert_id, decision_result.auto_verdict,
                            decision_result.auto_severity, score,
                        )
                        # In shadow mode, let the LLM determine the verdict
                        # naturally; log but do not override.
                    else:
                        result_data["severity"] = decision_result.auto_severity
                        result_data["category"] = decision_result.auto_verdict
                        result_data["escalation_required"] = True
                        result_data["confidence"] = max(result_data.get("confidence", 0.7), 0.90)

                # ── Output validation gate ──
                # Validate the fully-processed LLM result (fusion + overrides
                # applied) against the TriageResult schema.  Follows the
                # noise-gate pattern: try validate, on failure log and continue
                # with degraded-but-usable data — never drop the alert.

                result_data = validate_triage_output(result_data)
                if "_validation_error" in result_data:
                    val_error = result_data.pop("_validation_error")
                    logger.warning(
                        "LLM output validation degraded for alert %s: %s",
                        alert_id, val_error,
                    )
                    # Surface the validation error in the triage row's
                    # error_message so it's visible in the dashboard.
                    result_data["error"] = result_data.get("error") or val_error

                succeeded = result_data.get("success", True) is not False
                latency_ms = result_data.get("latency_ms")
                fields = dict(
                    model_name=provider.name(),
                    prompt_text=user_prompt,
                    response_text=json.dumps(result_data),
                    summary=result_data.get("summary", alert.rule_description),
                    category=result_data.get("category", "unknown"),
                    severity=result_data.get("severity", "medium"),
                    confidence=result_data.get("confidence", 0.5),
                    false_positive_likelihood=result_data.get("false_positive_likelihood", 0.3),
                    mitre_mapping=result_data.get("mitre_mapping", []),
                    investigation_steps=result_data.get(
                        "recommended_investigation_steps",
                        result_data.get("investigation_steps", []),
                    ),
                    do_not_do=result_data.get("do_not_do", []),
                    escalation_required=result_data.get("escalation_required", False),
                    suggested_soc_action=result_data.get("recommended_soc_action"),
                    success=succeeded,
                    error_message=result_data.get("error"),
                    status="completed" if succeeded else "failed",
                )

                # Manual path updates the pending row the API created; poller path
                # inserts a fresh row.
                triage = None
                if manual and triage_id:
                    triage = await session.get(AiTriageResult, uuid.UUID(str(triage_id)))
                if triage is not None:
                    for k, v in fields.items():
                        setattr(triage, k, v)
                else:
                    triage = AiTriageResult(alert_id=alert.id, tenant_id=alert.tenant_id, **fields)
                    session.add(triage)
                await session.flush()

                from shared.models.model_run import ModelRun
                from hashlib import sha256
                model_run = ModelRun(
                    tenant_id=alert.tenant_id,
                    model_name=provider.name(),
                    prompt_hash=sha256(user_prompt.encode()).hexdigest()[:16],
                    input_tokens=result_data.get("tokens_input"),
                    output_tokens=result_data.get("tokens_output"),
                    latency_ms=result_data.get("latency_ms"),
                    success=result_data.get("success", True),
                )
                session.add(model_run)

                if result_data.get("escalation_required", False):
                    # L3/L4 deterministic verdicts with incident risk tracking will
                    # create an incident-level auto-case below; skip the redundant
                    # per-alert escalation case to avoid duplicate cases.
                    if l3_l4_deterministic and incident and settings.incident_risk_enabled:
                        logger.info(
                            "Skipping escalation case for alert %s "
                            "(L3/L4 deterministic; incident risk tracking handles it)",
                            alert_id,
                        )
                    else:
                        level = alert.rule_level or 5
                        confidence = result_data.get("confidence", 0.5)
                        fp_likelihood = result_data.get("false_positive_likelihood", 0.3)
                        risk_score = round(confidence * (1 - fp_likelihood) * min(level / 15, 1) * 10, 2)

                        case = Case(
                            alert_id=alert.id,
                            incident_id=incident.id if incident else None,
                            title=result_data.get("summary", alert.rule_description or "Alert"),
                            severity=result_data.get("severity", "medium"),
                            category=result_data.get("category", "unknown"),
                            escalation_required=True,
                            risk_score=risk_score,
                        )
                        session.add(case)
                        await session.flush()

                        # Create investigation steps from AI result
                        for i, step_text in enumerate(result_data.get("investigation_steps", result_data.get("recommended_investigation_steps", []))):
                            step = CaseInvestigationStep(
                                case_id=case.id,
                                description=step_text if isinstance(step_text, str) else str(step_text),
                                order=i,
                            )
                            session.add(step)

                        # Auto-log case_created event
                        event = CaseEvent(
                            case_id=case.id,
                            event_type="case_created",
                            description=f"AI triage escalated: {case.title}",
                            event_meta={"model": provider.name(), "confidence": confidence},
                        )
                        session.add(event)

                # ── Cumulative incident risk tracking (S0) ──
                if incident and settings.incident_risk_enabled:
                    try:
                        # Add current alert's risk score to incident cumulative risk
                        incident_risk_delta = score
                        incident.cumulative_risk_score = (incident.cumulative_risk_score or 0) + incident_risk_delta
                        await session.flush()
                        logger.info(
                            "Incident %s cumulative risk updated: +%d → %d",
                            incident.id,
                            incident_risk_delta,
                            incident.cumulative_risk_score,
                        )

                        # Auto-case threshold check
                        if incident.cumulative_risk_score >= settings.incident_auto_case_threshold:
                            # Check if a case already exists for this incident's latest alert
                            existing_case_result = await session.execute(
                                select(Case).where(Case.alert_id == alert.id).limit(1)
                            )
                            if not existing_case_result.scalar_one_or_none():
                                if self._is_shadow_mode():
                                    logger.info(
                                        "[SHADOW] would auto-create case for incident %s "
                                        "(cumulative risk=%d >= threshold=%.0f)",
                                        incident.id,
                                        incident.cumulative_risk_score,
                                        settings.incident_auto_case_threshold,
                                    )
                                else:
                                    auto_case = Case(
                                        alert_id=alert.id,
                                        incident_id=incident.id,
                                        title=f"Auto-case: Incident {incident.id} (risk={incident.cumulative_risk_score})",
                                        severity="high",
                                        category="auto_case",
                                        escalation_required=True,
                                        risk_score=float(incident.cumulative_risk_score),
                                    )
                                    session.add(auto_case)
                                    await session.flush()
                                    auto_event = CaseEvent(
                                        case_id=auto_case.id,
                                        event_type="case_created",
                                        description=f"Auto-case: cumulative incident risk {incident.cumulative_risk_score} exceeded threshold {settings.incident_auto_case_threshold}",
                                        event_meta={
                                            "incident_id": str(incident.id),
                                            "cumulative_risk": incident.cumulative_risk_score,
                                            "threshold": settings.incident_auto_case_threshold,
                                        },
                                    )
                                    session.add(auto_event)
                                    logger.warning(
                                        "Auto-case created for incident %s (cumulative risk=%d >= threshold=%.0f)",
                                        incident.id,
                                        incident.cumulative_risk_score,
                                        settings.incident_auto_case_threshold,
                                    )
                    except Exception as risk_err:
                        logger.warning("Cumulative incident risk update failed for alert %s: %s", alert_id, risk_err)

                await session.commit()

                # ── Prometheus metrics ──
                # Record triage outcome and latency so the /metrics endpoint
                # can expose them to Prometheus on the next scrape.
                if self.redis_client:
                    try:
                        if succeeded:
                            await record_triage_success(self.redis_client)
                        else:
                            await record_triage_fail(self.redis_client)
                        await record_triage_latency(self.redis_client, latency_ms)
                    except Exception:
                        pass  # metrics are best-effort — never fail a triage for them

                # Persist the triage verdict for future RAG retrieval and cache it
                # for near-duplicate alerts.
                try:
                    verdict_for_rag = {
                        "triage_id": str(triage.id),
                        **fields,
                    }
                    if not result_data.get("_cached") and semantic_cache_obj is not None:
                        await semantic_cache_obj.store(
                            alert_features,
                            verdict_for_rag,
                            ttl=settings.triage_cache_ttl_seconds,
                        )
                    await triage_rag.persist_triage_verdict(session, alert, verdict_for_rag)
                    await session.commit()
                except Exception as cache_err:
                    logger.warning("Triage cache/RAG persist failed for alert %s: %s", alert_id, cache_err)

                # UEBA: update baselines and detect anomalies
                try:
                    from shared.ueba.detector import process_alert
                    anomalies = await process_alert(session, alert, str(alert.tenant_id) if alert.tenant_id else None)
                    if anomalies:
                        await session.commit()
                        logger.info("UEBA: %d anomalies for alert %s", len(anomalies), alert_id)
                except Exception as ueba_err:
                    logger.warning("UEBA analysis failed for alert %s: %s", alert_id, ueba_err)

                # SOAR: run matching playbooks
                try:
                    from shared.soar.engine import SOAREngine
                    alert_dict = {
                        "id": str(alert.id),
                        "rule_level": alert.rule_level,
                        "rule_description": alert.rule_description,
                        "severity": result_data.get("severity", "medium"),
                        "source_ip": alert.source_ip,
                        "user_name": alert.user_name,
                        "agent_name": alert.agent_name,
                        "mitre_tactic": alert.mitre_tactic,
                        "escalation_required": result_data.get("escalation_required", False),
                    }
                    soar = SOAREngine(session=session, redis_client=self.redis_client)
                    playbook_results = await soar.run_for_alert(alert_dict)
                    if playbook_results:
                        logger.info("SOAR: %d playbooks ran for alert %s", len(playbook_results), alert_id)
                except Exception as soar_err:
                    logger.warning("SOAR execution failed for alert %s: %s", alert_id, soar_err)

                # Push to TI enrichment queue
                if self.redis_client:
                    await self.redis_client.lpush(
                        "ti_enrich_queue",
                        json.dumps({"alert_id": str(alert_id)}),
                    )

                logger.info("Triage completed for alert %s", alert_id)

        except Exception as e:
            logger.error("Failed to process triage for alert %s: %s", alert_id, e, exc_info=True)
            # Fail the manual pending row so the dashboard stops polling.
            await self._mark_manual_failed(triage_id, str(e))
            # Record failure metric
            if self.redis_client:
                try:
                    await record_triage_fail(self.redis_client)
                except Exception:
                    pass
            # Push to dead-letter queue so no job is silently lost
            if self.redis_client:
                await self.redis_client.lpush(
                    "triage_dlq",
                    json.dumps({"alert_id": alert_id, "error": str(e)}),
                )

    async def _mark_manual_failed(self, triage_id, error: str):
        """Mark an API-created pending triage row as failed (manual path only)."""
        if not triage_id:
            return
        try:
            async with self.session_factory() as session:
                row = await session.get(AiTriageResult, uuid.UUID(str(triage_id)))
                if row is not None:
                    row.status = "failed"
                    row.success = False
                    row.error_message = error[:500]
                    await session.commit()
        except Exception as exc:
            logger.warning("Could not mark triage %s failed: %s", triage_id, exc)

    async def stop(self):
        self._shutdown = True
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = TriageWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
