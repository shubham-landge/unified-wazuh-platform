import asyncio
import json
import logging
from pathlib import Path
import redis.asyncio as redis
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings
from shared.models.knowledge_base import KnowledgeChunk
from shared.rag.vector_store import chunk_and_ingest
from sqlalchemy import select

logger = logging.getLogger(__name__)

SOC_PLAYBOOK_DIRS = [
    Path(__file__).resolve().parent.parent.parent.parent / "shared" / "rag" / "kb",
]


class RAGWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=5)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        self.redis_client: redis.Redis | None = None

    async def start(self):
        self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("RAG worker started. Waiting for ingestion jobs...")

        await self._ingest_builtin_kb()

        while True:
            try:
                item = await self.redis_client.brpop("rag_ingest_queue", timeout=10)
                if item:
                    _, msg = item
                    await self.process_message(json.loads(msg))
            except TypeError:
                continue
            except Exception as e:
                logger.error("RAG worker error: %s", e, exc_info=True)
                await asyncio.sleep(1)

    async def _ingest_builtin_kb(self):
        for kb_dir in SOC_PLAYBOOK_DIRS:
            if not kb_dir.exists():
                kb_dir.mkdir(parents=True, exist_ok=True)
                kb_dir.joinpath("soc_playbook_intro.md").write_text(
                    "# SOC Triage Playbook\n\n"
                    "## Initial Triage\n"
                    "- Verify alert severity using rule_level\n"
                    "- Check if source IP is in known bad IP lists\n"
                    "- Review MITRE ATT&CK mapping for context\n"
                    "- Look up past similar incidents\n\n"
                    "## Escalation Criteria\n"
                    "- Rule level >= 10: escalate to senior analyst\n"
                    "- Known malware indicator: escalate immediately\n"
                    "- Critical asset involved: prioritize over other alerts\n\n"
                    "## Containment Steps\n"
                    "- Isolate affected agent via Wazuh API\n"
                    "- Block source IP at firewall if lateral movement detected\n"
                    "- Collect full memory/disk forensic image\n"
                )

            async with self.session_factory() as session:
                # Skip seeding if any built-in playbook chunks already exist.
                existing = await session.execute(
                    select(KnowledgeChunk).where(KnowledgeChunk.source.ilike("soc_playbook%")).limit(1)
                )
                if existing.scalar_one_or_none():
                    logger.info("Built-in KB chunks already present; skipping seed.")
                    continue

                for f in kb_dir.glob("*.md"):
                    text = f.read_text()
                    await chunk_and_ingest(
                        source=f.name,
                        full_text=text,
                        db=session,
                        chunk_size=500,
                        overlap=50,
                        metadata={"type": "soc_playbook", "file": f.name},
                    )

    async def process_message(self, msg: dict):
        source = msg.get("source")
        text = msg.get("text")
        metadata = msg.get("metadata", {})
        if not source or not text:
            logger.warning("Invalid ingestion message: %s", msg)
            return

        async with self.session_factory() as session:
            await chunk_and_ingest(source, text, session, metadata=metadata)
            logger.info("Ingested knowledge from %s", source)

    async def stop(self):
        if self.redis_client:
            await self.redis_client.close()
        await self.engine.dispose()
