"""
SOAR Playbook Engine

Loads active playbooks from the DB, evaluates trigger conditions against
incoming alert/case dicts, and executes matched playbooks in priority order.
"""
import logging
import operator
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shared.models.playbook import Playbook, PlaybookRun
from shared.soar.actions import ActionContext, execute_action

logger = logging.getLogger(__name__)

_OPS = {
    "eq":       operator.eq,
    "ne":       operator.ne,
    "gt":       operator.gt,
    "gte":      operator.ge,
    "lt":       operator.lt,
    "lte":      operator.le,
    "in":       lambda a, b: a in b,
    "not_in":   lambda a, b: a not in b,
    "contains": lambda a, b: b in str(a),
    "exists":   lambda a, _: a is not None,
}


def _evaluate_condition(condition: dict, alert: dict) -> bool:
    """Recursively evaluate a trigger condition against an alert dict."""
    if "and" in condition:
        return all(_evaluate_condition(c, alert) for c in condition["and"])
    if "or" in condition:
        return any(_evaluate_condition(c, alert) for c in condition["or"])
    if "not" in condition:
        return not _evaluate_condition(condition["not"], alert)

    field = condition.get("field", "")
    op_name = condition.get("op", "eq")
    expected = condition.get("value")

    actual = alert.get(field)

    op_func = _OPS.get(op_name)
    if not op_func:
        logger.warning("Unknown SOAR operator: %s", op_name)
        return False

    try:
        return bool(op_func(actual, expected))
    except Exception:
        return False


class SOAREngine:
    def __init__(self, session: AsyncSession, redis_client=None):
        self.session = session
        self.redis_client = redis_client

    async def run_for_alert(self, alert: dict) -> list[dict]:
        """Find and execute all matching playbooks for an alert. Returns list of run results."""
        playbooks = await self._load_active_playbooks()
        results = []
        for pb in playbooks:
            if _evaluate_condition(pb.trigger, alert):
                logger.info("Playbook '%s' triggered for alert %s", pb.name, alert.get("id"))
                result = await self._execute_playbook(pb, alert)
                results.append(result)
        return results

    async def _load_active_playbooks(self) -> list[Playbook]:
        q = select(Playbook).where(Playbook.is_active == True).order_by(Playbook.priority)
        res = await self.session.execute(q)
        return list(res.scalars().all())

    async def _execute_playbook(self, playbook: Playbook, alert: dict) -> dict:
        run = PlaybookRun(
            playbook_id=playbook.id,
            alert_id=alert.get("id"),
            status="running",
            actions_total=len(playbook.actions),
            started_at=datetime.now(timezone.utc),
        )
        self.session.add(run)
        await self.session.flush()

        ctx = ActionContext(
            alert=alert,
            session=self.session,
            redis_client=self.redis_client,
        )

        action_results = []
        for i, action in enumerate(playbook.actions):
            action_result = await execute_action(action, ctx)
            action_results.append(action_result)
            run.actions_completed = i + 1

            if not action_result.get("success") and not action.get("continue_on_error", True):
                run.status = "failed"
                run.error = action_result.get("error")
                break
        else:
            run.status = "completed"

        run.completed_at = datetime.now(timezone.utc)
        run.result = {"actions": action_results, "case_id": ctx.case_id}
        await self.session.commit()

        logger.info(
            "Playbook '%s' %s in %.0fms | %d/%d actions",
            playbook.name,
            run.status,
            (run.completed_at - run.started_at).total_seconds() * 1000,
            run.actions_completed,
            run.actions_total,
        )
        return {
            "playbook_name": playbook.name,
            "run_id": str(run.id),
            "status": run.status,
            "actions_completed": run.actions_completed,
            "case_id": ctx.case_id,
        }
