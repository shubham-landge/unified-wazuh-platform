import asyncio
import json
import logging
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
from shared.connectors.llm_provider import get_provider
from shared.connectors.llm_router import TieredRouter

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


class TriageWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None

    async def start(self):
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Triage worker started. Waiting for alerts...")

        while True:
            try:
                item = await self.redis_client.brpop("triage_queue", timeout=5)
                if item:
                    _, msg = item
                    await self.process_message(json.loads(msg))
            except TypeError:
                continue
            except Exception as e:
                logger.error("Triage worker error: %s", e, exc_info=True)
                await asyncio.sleep(1)

    async def process_message(self, msg: dict):
        alert_id = msg.get("alert_id")
        if not alert_id:
            return

        logger.info("Processing triage for alert %s", alert_id)

        try:
            async with self.session_factory() as session:
                result = await session.execute(select(Alert).where(Alert.id == alert_id))
                alert = result.scalar_one_or_none()
                if not alert:
                    logger.warning("Alert %s not found", alert_id)
                    return

                provider = TieredRouter().get_provider(alert=alert, tenant_id=str(alert.tenant_id))
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
                )

                result_data = await provider.analyze(
                    system_prompt=TRIAGE_PROMPT_SYSTEM,
                    user_prompt=user_prompt,
                )

                triage = AiTriageResult(
                    alert_id=alert.id,
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
                    success=result_data.get("success", True),
                    error_message=result_data.get("error"),
                )
                session.add(triage)
                await session.flush()

                if result_data.get("escalation_required", False):
                    level = alert.rule_level or 5
                    confidence = result_data.get("confidence", 0.5)
                    fp_likelihood = result_data.get("false_positive_likelihood", 0.3)
                    risk_score = round(confidence * (1 - fp_likelihood) * min(level / 15, 1) * 10, 2)

                    case = Case(
                        alert_id=alert.id,
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

                await session.commit()

                # UEBA: update baselines and detect anomalies
                try:
                    from shared.ueba.detector import analyze_alert
                    anomalies = await analyze_alert(session, alert)
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
            # Push to dead-letter queue so no job is silently lost
            if self.redis_client:
                await self.redis_client.lpush(
                    "triage_dlq",
                    json.dumps({"alert_id": alert_id, "error": str(e)}),
                )

    async def stop(self):
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
