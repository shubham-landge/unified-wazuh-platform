import asyncio
import logging
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from shared.config import settings
from shared.models.alert import Alert
from shared.models.ai_triage_result import AiTriageResult
from shared.rag.skill_memory import add_experience
from shared.models.agent import AgentTask

logger = logging.getLogger(__name__)

class MetaAgent:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def start(self):
        while True:
            try:
                await self.scan_missed_detections()
            except Exception as e:
                logger.error("Meta agent missed-detection scan error: %s", e)
            await asyncio.sleep(86400)

    async def scan_missed_detections(self):
        async with self.session_factory() as session:
            stmt = select(Alert).outerjoin(AiTriageResult, Alert.id == AiTriageResult.alert_id).where(AiTriageResult.id.is_(None))
            res = await session.execute(stmt)
            missed_alerts = res.scalars().all()
            if not missed_alerts:
                return

            for alert in missed_alerts:
                task = AgentTask(
                    agent_type="meta_agent",
                    input_data={"alert_id": str(alert.id), "rule_description": alert.rule_description},
                    output_data={"triage_status": "missed_detection_ingested"},
                    status="completed"
                )
                await add_experience(session, task)
            await session.commit()

    async def stop(self):
        await self.engine.dispose()
