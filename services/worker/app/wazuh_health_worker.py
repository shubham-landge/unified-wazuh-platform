"""Wazuh Environment Health worker.

Polls the Wazuh environment (agents, manager/cluster, indexer/ingestion) and our
own pipeline (poller heartbeat, triage queue depth), writes a snapshot row, and
publishes Prometheus gauge values to Redis. When a threshold trips it raises an
internal alert so the SOC notices that *Wazuh itself* is unhealthy — the thing
Wazuh's own UI surfaces poorly.

This is what makes the platform an overlay/observer of Wazuh, not a Wazuh clone.
"""
import asyncio
import logging
from datetime import datetime, timezone

import redis.asyncio as redis
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shared.config import settings
from shared.connectors.wazuh_api import WazuhAPIConnector
from shared.connectors.wazuh_indexer import WazuhIndexerConnector
from shared.models.wazuh_health import WazuhHealthSnapshot

logger = logging.getLogger(__name__)


class WazuhHealthWorker:
    def __init__(self, session_factory=None, redis_client=None):
        self.engine = None
        if session_factory is None:
            self.engine = create_async_engine(settings.database_url, pool_size=2)
            self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        else:
            self.session_factory = session_factory
        self.redis_client = redis_client
        self._stopped = asyncio.Event()

    async def start(self):
        if not settings.wazuh_health_enabled:
            logger.info("Wazuh health monitoring disabled. Skipping.")
            return
        if self.redis_client is None:
            self.redis_client = await redis.from_url(settings.redis_url, decode_responses=True)
        logger.info("Wazuh health worker started. Interval: %ds", settings.wazuh_health_poll_interval_seconds)
        while not self._stopped.is_set():
            try:
                await self.collect_once()
            except Exception as exc:
                logger.error("Wazuh health collection failed: %s", exc, exc_info=True)
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=settings.wazuh_health_poll_interval_seconds)
            except asyncio.TimeoutError:
                pass

    async def stop(self):
        self._stopped.set()
        if self.engine:
            await self.engine.dispose()

    async def collect_once(self) -> dict:
        snapshot = await self._build_snapshot()
        async with self._session_ctx() as session:
            session.add(snapshot)
            await session.commit()
        await self._publish_metrics(snapshot)
        if snapshot.overall_status != "healthy":
            logger.warning("Wazuh environment %s: %s", snapshot.overall_status, snapshot.issues)
        return {
            "status": snapshot.overall_status,
            "issues": snapshot.issues,
            "agents_disconnected": snapshot.agents_disconnected,
        }

    def _session_ctx(self):
        factory = self.session_factory
        if hasattr(factory, "__aenter__"):
            return factory
        return factory()

    async def _build_snapshot(self) -> WazuhHealthSnapshot:
        managers = settings.parsed_wazuh_managers or [{"label": "default", "url": settings.wazuh_api_url,
                                                       "user": settings.wazuh_api_user, "password": ""}]
        indexers = settings.parsed_wazuh_indexers or [{"label": "default", "url": settings.wazuh_indexer_url,
                                                       "user": settings.wazuh_indexer_user, "password": ""}]

        mgr = managers[0]
        api = WazuhAPIConnector(base_url=mgr["url"], user=mgr["user"],
                                password=mgr["password"], label=mgr["label"])
        agents, cluster, stats, status = await asyncio.gather(
            api.get_agents_summary(), api.get_cluster_health(),
            api.get_manager_stats(), api.get_manager_status(),
        )
        await api.close()

        idx = indexers[0]
        indexer = WazuhIndexerConnector(base_url=idx["url"], user=idx["user"],
                                        password=idx["password"], label=idx["label"])
        idx_health, lag = await asyncio.gather(
            indexer.cluster_health(), indexer.ingestion_lag_seconds(),
        )
        await indexer.close()

        poller_lag, queue_depth = await self._self_sla()

        issues = self._evaluate(agents, cluster, stats, status, idx_health, lag)
        overall = "unhealthy" if any(i["severity"] == "critical" for i in issues) else (
            "degraded" if issues else "healthy")

        return WazuhHealthSnapshot(
            tenant_id=None,
            manager_label=mgr["label"],
            captured_at=datetime.now(timezone.utc),
            agents_active=agents.get("active", 0),
            agents_disconnected=agents.get("disconnected", 0),
            agents_never_connected=agents.get("never_connected", 0),
            agents_pending=agents.get("pending", 0),
            agents_total=agents.get("total", 0),
            cluster_status=cluster.get("status", "unknown"),
            manager_all_running=status.get("all_running", True),
            analysisd_eps=float(stats.get("events_received", 0) or 0),
            analysisd_queue_pct=float(stats.get("event_queue_usage", 0.0) or 0.0),
            events_dropped=int(stats.get("events_dropped", 0) or 0),
            indexer_status=idx_health.get("status", "unknown"),
            indexer_unassigned_shards=idx_health.get("unassigned_shards", 0),
            ingestion_lag_seconds=lag,
            self_poller_lag_seconds=poller_lag,
            self_triage_queue_depth=queue_depth,
            overall_status=overall,
            issues=issues,
            raw={"agents": agents, "cluster": cluster, "stats": stats,
                 "status": status, "indexer": idx_health},
        )

    async def _self_sla(self) -> tuple[float | None, int]:
        poller_lag = None
        queue_depth = 0
        try:
            last_run = await self.redis_client.get("poller:last_run")
            if last_run:
                ts = datetime.fromisoformat(last_run)
                poller_lag = max(0.0, (datetime.now(timezone.utc) - ts).total_seconds())
            queue_depth = int(await self.redis_client.llen("triage_queue") or 0)
        except Exception as exc:
            logger.debug("self-SLA read skipped: %s", exc)
        return poller_lag, queue_depth

    def _evaluate(self, agents, cluster, stats, status, idx_health, lag) -> list[dict]:
        issues: list[dict] = []
        total = agents.get("total", 0) or 0
        disconnected = agents.get("disconnected", 0) or 0
        if total and (disconnected / total) >= settings.wazuh_health_agent_disconnect_pct_warn:
            issues.append({"severity": "warning", "code": "agents_disconnected",
                           "detail": f"{disconnected}/{total} agents disconnected"})
        if not status.get("all_running", True):
            issues.append({"severity": "critical", "code": "manager_daemon_down",
                           "detail": f"stopped: {status.get('stopped')}"})
        if cluster.get("status") == "error":
            issues.append({"severity": "warning", "code": "cluster_unreachable",
                           "detail": cluster.get("error", "cluster healthcheck failed")})
        if idx_health.get("status") == "red":
            issues.append({"severity": "critical", "code": "indexer_red",
                           "detail": "indexer cluster status RED"})
        elif idx_health.get("status") == "yellow":
            issues.append({"severity": "warning", "code": "indexer_yellow",
                           "detail": f"{idx_health.get('unassigned_shards')} unassigned shards"})
        if lag is not None and lag >= settings.wazuh_health_ingestion_lag_warn_seconds:
            issues.append({"severity": "warning", "code": "ingestion_lag",
                           "detail": f"newest alert is {int(lag)}s old"})
        if (stats.get("events_dropped", 0) or 0) >= settings.wazuh_health_events_dropped_warn:
            issues.append({"severity": "warning", "code": "events_dropped",
                           "detail": f"analysisd dropped {stats.get('events_dropped')} events"})
        return issues

    async def _publish_metrics(self, snap: WazuhHealthSnapshot):
        """Publish gauge values to Redis for the API /metrics endpoint to read."""
        try:
            status_code = {"green": 0, "yellow": 1, "red": 2}.get(snap.indexer_status, 3)
            mapping = {
                "wazuh_agents_disconnected": snap.agents_disconnected,
                "wazuh_agents_active": snap.agents_active,
                "wazuh_cluster_status_code": status_code,
                "wazuh_analysisd_eps": snap.analysisd_eps,
                "wazuh_ingestion_lag_seconds": snap.ingestion_lag_seconds or 0,
                "wazuh_poller_lag_seconds": snap.self_poller_lag_seconds or 0,
            }
            for k, v in mapping.items():
                await self.redis_client.set(k, float(v))
        except Exception as exc:
            logger.debug("metric publish skipped: %s", exc)


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = WazuhHealthWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
