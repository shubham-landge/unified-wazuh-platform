import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shared.models.agent import AgentDefinition, AgentRun, AgentTask

logger = logging.getLogger(__name__)


class OrchestrationEngine:
    def __init__(self, session_factory: async_sessionmaker | None = None):
        self._registry: dict[str, Callable] = {}
        self._session_factory = session_factory

    def register_agent(self, name: str, handler: Callable) -> None:
        self._registry[name] = handler
        logger.debug("Registered agent handler: %s", name)

    async def create_run(
        self,
        definition_id: uuid.UUID,
        tenant_id: uuid.UUID | None,
        trigger_type: str = "manual",
        trigger_ref: str | None = None,
        session: AsyncSession | None = None,
    ) -> AgentRun:
        run = AgentRun(
            definition_id=definition_id,
            tenant_id=tenant_id,
            trigger_type=trigger_type,
            trigger_ref=trigger_ref,
            status="pending",
        )
        if session is not None:
            session.add(run)
            await session.flush()
            return run

        async with self._session_factory() as s:
            s.add(run)
            await s.commit()
            await s.refresh(run)
        return run

    async def execute_run(self, run_id: uuid.UUID) -> None:
        async with self._session_factory() as session:
            result = await session.execute(select(AgentRun).where(AgentRun.id == run_id))
            run = result.scalar_one_or_none()
            if not run:
                logger.warning("AgentRun %s not found", run_id)
                return

            defn_result = await session.execute(
                select(AgentDefinition).where(AgentDefinition.id == run.definition_id)
            )
            definition = defn_result.scalar_one_or_none()

            run.status = "running"
            run.started_at = datetime.now(timezone.utc)
            await session.flush()

            try:
                tasks_cfg = definition.config.get("tasks", []) if definition else []

                for task_cfg in tasks_cfg:
                    agent_type = task_cfg.get("agent_type", "unknown")
                    task = AgentTask(
                        run_id=run.id,
                        agent_type=agent_type,
                        input_data=task_cfg.get("input", {}),
                        status="running",
                        started_at=datetime.now(timezone.utc),
                    )
                    session.add(task)
                    await session.flush()

                    handler = self._registry.get(agent_type)
                    if handler:
                        try:
                            output = await handler(task_cfg.get("input", {}))
                            task.output_data = output if isinstance(output, dict) else {"result": str(output)}
                            task.status = "completed"
                        except Exception as exc:
                            task.status = "failed"
                            task.error = str(exc)
                            logger.error("Task %s failed: %s", task.id, exc)
                    else:
                        task.output_data = {}
                        task.status = "completed"

                    task.completed_at = datetime.now(timezone.utc)

                run.status = "completed"
                run.result_summary = f"Executed {len(tasks_cfg)} task(s)"

            except Exception as exc:
                run.status = "failed"
                run.result_summary = str(exc)
                logger.error("AgentRun %s failed: %s", run_id, exc)

            run.completed_at = datetime.now(timezone.utc)
            await session.commit()
