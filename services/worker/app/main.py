import asyncio
import logging

from .poller import AlertPoller
from .triage_worker import TriageWorker
from .vulnerability_worker import VulnerabilityWorker


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    poller = AlertPoller()
    triage_worker = TriageWorker()
    vulnerability_worker = VulnerabilityWorker()
    tasks = [
        asyncio.create_task(poller.start()),
        asyncio.create_task(triage_worker.start()),
        asyncio.create_task(vulnerability_worker.start()),
    ]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await poller.stop()
        await triage_worker.stop()
        await vulnerability_worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
