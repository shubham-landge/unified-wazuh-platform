import asyncio
import importlib
import logging

WORKER_SPECS = [
    ("app.poller", "AlertPoller"),
    ("app.triage_worker", "TriageWorker"),
    ("app.vulnerability_worker", "VulnerabilityWorker"),
    ("app.osint_worker", "OSINTWorker"),
]


def _build_worker(module_name: str, class_name: str):
    module = importlib.import_module(module_name)
    return getattr(module, class_name)()


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    workers = [_build_worker(module_name, class_name) for module_name, class_name in WORKER_SPECS]
    tasks = [asyncio.create_task(worker.start()) for worker in workers]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*(worker.stop() for worker in workers), return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
