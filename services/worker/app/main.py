import asyncio
import logging

from .poller import AlertPoller
from .triage_worker import TriageWorker
from .vulnerability_worker import VulnerabilityWorker

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


async def main():
    poller = AlertPoller()
    triage_worker = TriageWorker()
    vulnerability_worker = VulnerabilityWorker()

    workers = [poller, triage_worker, vulnerability_worker]

    # Auto-discover optional future workers
    for module_name, class_name in [
        ("app.notification_worker", "NotificationWorker"),
        ("app.playbook_worker", "PlaybookWorker"),
        ("app.threat_intel_worker", "ThreatIntelWorker"),
        ("app.ueba_worker", "UEBAWorker"),
        ("app.feedback_worker", "FeedbackWorker"),
        ("app.approval_worker", "ApprovalWorker"),
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

    tasks = [asyncio.create_task(w.start()) for w in workers]

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
