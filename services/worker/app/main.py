import asyncio
import logging

from .poller import AlertPoller
from .triage_worker import TriageWorker
from .vulnerability_worker import VulnerabilityWorker
from .vuln_ingester import VulnIngester

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


async def main():
    poller = AlertPoller()
    triage_worker = TriageWorker()
    vulnerability_worker = VulnerabilityWorker()
    vuln_ingester = VulnIngester()

    workers = [poller, triage_worker, vulnerability_worker, vuln_ingester]

    for module_name, class_name in [
        ("app.notification_worker", "NotificationWorker"),
        ("app.playbook_worker", "PlaybookWorker"),
        ("app.threat_intel_worker", "ThreatIntelWorker"),
        ("app.ueba_worker", "UEBAWorker"),
        ("app.feedback_worker", "FeedbackWorker"),
        ("app.rag_worker", "RAGWorker"),
        ("app.agent_worker", "AgentWorker"),
        ("app.ticketing_worker", "TicketingWorker"),
        ("app.approval_worker", "ApprovalWorker"),
        ("app.osint_worker", "OSINTWorker"),
        ("app.identity_worker", "IdentityWorker"),
        ("app.wazuh_health_worker", "WazuhHealthWorker"),
    ]:
        try:
            import importlib
            module = importlib.import_module(module_name)
            cls = getattr(module, class_name)
            workers.append(cls())
            logger.info("Discovered optional worker: %s", module_name)
        except (ImportError, AttributeError):
            pass

    logger.info("Starting %d workers", len(workers))

    async def _run_worker(worker, restart_delay: float = 5.0):
        name = worker.__class__.__name__
        while True:
            try:
                await worker.start()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception("Worker %s crashed: %s", name, exc)
                try:
                    await worker.stop()
                except Exception:
                    pass
                logger.info("Restarting worker %s in %.1f seconds", name, restart_delay)
                await asyncio.sleep(restart_delay)
            else:
                await asyncio.sleep(restart_delay)

    tasks = [asyncio.create_task(_run_worker(w)) for w in workers]

    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        logger.info("Shutting down workers...")
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for w in workers:
            try:
                await w.stop()
            except Exception:
                pass


if __name__ == "__main__":
    asyncio.run(main())
