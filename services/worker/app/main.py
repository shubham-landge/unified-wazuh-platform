import asyncio
import logging
import importlib

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


async def start_worker(module_path: str, class_name: str):
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    instance = cls()
    await instance.start()


async def main():
    workers = [
        ("app.poller", "AlertPoller"),
        ("app.triage_worker", "TriageWorker"),
    ]

    # Auto-discover optional workers (e.g., vulnerability_worker from Codex)
    for extra in ["app.vulnerability_worker"]:
        try:
            importlib.import_module(extra)
            workers.append((extra, "VulnerabilityWorker"))
            logger.info("Discovered optional worker: %s", extra)
        except (ImportError, AttributeError):
            pass

    logger.info("Starting %d workers: %s", len(workers), [w[0] for w in workers])

    tasks = [
        asyncio.create_task(start_worker(mod, cls), name=mod)
        for mod, cls in workers
    ]

    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        logger.info("Shutting down workers...")
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
