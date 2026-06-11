import asyncio
import json
import logging
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings
from shared.models.alert import Alert
from shared.models.ai_triage_result import AiTriageResult
from shared.models.case import Case
from shared.connectors.llm_provider import get_provider

logger = logging.getLogger(__name__)

TRIAGE_PROMPT_SYSTEM = """You are a defensive SOC triage copilot for Wazuh.
Analyze the following Wazuh alert and provide structured output.
Be concise and accurate. Never recommend destructive actions.
Output valid JSON only."""


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
                _, msg = await self.redis_client.brpop("triage_queue", timeout=5)
                if msg:
                    await self.process_message(json.loads(msg))
            except TypeError:
                continue
            except Exception as e:
                logger.error("Triage worker error: %s", e, exc_info=True)

    async def process_message(self, msg: dict):
        alert_id = msg.get("alert_id")
        if not alert_id:
            return

        logger.info("Processing triage for alert %s", alert_id)

            from sqlalchemy import select

            async with self.session_factory() as session:
            result = await session.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert:
                logger.warning("Alert %s not found", alert_id)
                return

            provider = get_provider()

            user_prompt = f"""
Alert Rule: {alert.rule_description}
Rule ID: {alert.rule_id}
Level: {alert.rule_level}
Groups: {alert.rule_groups}
Agent: {alert.agent_name} ({alert.agent_ip})
Source IP: {alert.source_ip}
User: {alert.user_name}
Process: {alert.process_name}
MITRE: {alert.mitre_tactic} / {alert.mitre_technique}
"""

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
                investigation_steps=result_data.get("investigation_steps", []),
                do_not_do=result_data.get("do_not_do", []),
                escalation_required=result_data.get("escalation_required", False),
                suggested_soc_action=result_data.get("recommended_soc_action"),
                success=result_data.get("success", True),
                error_message=result_data.get("error"),
            )
            session.add(triage)
            await session.flush()

            if result_data.get("escalation_required", False):
                case = Case(
                    alert_id=alert.id,
                    title=result_data.get("summary", alert.rule_description or "Alert"),
                    severity=result_data.get("severity", "medium"),
                    category=result_data.get("category", "unknown"),
                    escalation_required=True,
                )
                session.add(case)

            await session.commit()
            logger.info("Triage completed for alert %s", alert_id)

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
