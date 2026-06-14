import asyncio
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from shared.config import settings
from shared.models.agent import AgentDefinition, AgentRun, AgentTask
from shared.rag import skill_memory

logger = logging.getLogger(__name__)


@dataclass
class HandlerContext:
    """Runtime context passed to every agent handler."""

    session: AsyncSession
    run: AgentRun
    task: AgentTask
    prev_output: dict[str, Any] | None = None


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
                prev_output: dict[str, Any] = {}

                i = 0
                while i < len(tasks_cfg):
                    # Build a parallel group: the current task plus any following task
                    # marked with "parallel": true.
                    group = [tasks_cfg[i]]
                    while (
                        i + 1 < len(tasks_cfg)
                        and tasks_cfg[i + 1].get("parallel") is True
                    ):
                        group.append(tasks_cfg[i + 1])
                        i += 1

                    if len(group) == 1:
                        prev_output = await self._run_task(
                            session, run, group[0], prev_output
                        )
                    else:
                        # Independent tasks in the group receive the same prev_output
                        # and their outputs are merged afterwards.
                        outputs = await asyncio.gather(
                            *(
                                self._run_task(session, run, cfg, prev_output)
                                for cfg in group
                            )
                        )
                        merged: dict[str, Any] = {}
                        for out in outputs:
                            if isinstance(out, dict):
                                merged.update(out)
                        prev_output = merged

                    i += 1

                run.status = "completed"
                run.result_summary = f"Executed {len(tasks_cfg)} task(s)"

            except Exception as exc:
                run.status = "failed"
                run.result_summary = str(exc)
                logger.error("AgentRun %s failed: %s", run_id, exc)

            run.completed_at = datetime.now(timezone.utc)
            await session.commit()

    async def _run_task(
        self,
        session: AsyncSession,
        run: AgentRun,
        task_cfg: dict,
        prev_output: dict[str, Any] | None,
    ) -> dict[str, Any]:
        agent_type = task_cfg.get("agent_type", "unknown")

        # Output chaining: previous task output is merged into this task's input.
        # Explicit task input takes precedence over inherited keys.
        task_input = task_cfg.get("input", {}) or {}
        chained_input = {**(prev_output or {}), **task_input}

        task = AgentTask(
            run_id=run.id,
            agent_type=agent_type,
            input_data=chained_input,
            status="running",
            started_at=datetime.now(timezone.utc),
        )
        session.add(task)
        await session.flush()

        handler = self._registry.get(agent_type)
        if handler:
            try:
                ctx = HandlerContext(
                    session=session, run=run, task=task, prev_output=prev_output
                )
                output = await handler(chained_input, ctx)
                task.output_data = output if isinstance(output, dict) else {"result": str(output)}
                task.status = "completed"
            except Exception as exc:
                task.status = "failed"
                task.error = str(exc)
                logger.error("Task %s (%s) failed: %s", task.id, agent_type, exc)
                task.output_data = {"error": str(exc)}
        else:
            logger.warning("No handler registered for agent type: %s", agent_type)
            task.output_data = {}
            task.status = "completed"

        task.completed_at = datetime.now(timezone.utc)

        if settings.rag_skill_memory_enabled and task.status == "completed":
            try:
                await skill_memory.add_experience(session, task)
            except Exception as exc:
                logger.warning("Failed to store skill memory for task %s: %s", task.id, exc)

        return task.output_data or {}
