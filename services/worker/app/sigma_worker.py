"""Sigma rule worker — compiles Sigma rules to Wazuh Indexer DSL and
runs them on schedule, raising alerts on matches.

This is a minimal implementation. For full Sigma support, install
the `sigma` Python package in the deployment environment.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from shared.config import settings

logger = logging.getLogger(__name__)


# Inline minimal Sigma-to-DSL compiler for common log sources.
# Replace with `sigma` library in production.
_SIGMA_RULES: list[dict] = [
    {
        "id": "SIGMA-001",
        "title": "Suspicious PowerShell Execution",
        "description": "Detects suspicious PowerShell command-line flags",
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"keywords": ["-EncodedCommand", "-ExecutionPolicy Bypass", "Invoke-Expression"]},
        "level": "high",
    },
    {
        "id": "SIGMA-002",
        "title": "Potential C2 Communication",
        "description": "Detects outbound connections to known bad IPs or unusual ports",
        "logsource": {"category": "network_connection", "product": "windows"},
        "detection": {"ports": [4444, 8443, 1337], "unknown_outbound": True},
        "level": "critical",
    },
]


def _compile_to_wazuh_dsl(rule: dict) -> dict:
    """Convert a Sigma rule dict to a Wazuh Indexer DSL query fragment."""
    detection = rule.get("detection", {})
    keywords = detection.get("keywords", [])
    ports = detection.get("ports", [])
    must_clauses = []

    for kw in keywords:
        must_clauses.append({"match_phrase": {"data": kw}})

    for port in ports:
        must_clauses.append({"term": {"destination_port": port}})

    if detection.get("unknown_outbound"):
        must_clauses.append({"exists": {"field": "destination_ip"}})

    return {
        "query": {
            "bool": {
                "must": must_clauses if must_clauses else [{"match_all": {}}],
                "filter": [{"range": {"@timestamp": {"gte": "now-1h"}}}],
            }
        },
        "size": 100,
    }


class SigmaWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=2)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def run_cycle(self):
        """Run each Sigma rule against the Wazuh indexer and log matches."""
        indexer_url = settings.wazuh_indexer_url
        auth = (settings.wazuh_indexer_user, settings.wazuh_indexer_password.get_secret_value())
        verify = settings.wazuh_indexer_verify_ssl

        for rule in _SIGMA_RULES:
            query = _compile_to_wazuh_dsl(rule)
            try:
                async with httpx.AsyncClient(verify=verify, auth=auth, timeout=30.0) as client:
                    resp = await client.post(
                        f"{indexer_url}/wazuh-alerts-*/_search",
                        json=query,
                        headers={"Content-Type": "application/json"},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                    hits = data.get("hits", {}).get("hits", [])
                    if hits:
                        logger.info(
                            "Sigma rule %s (%s): %d matches",
                            rule["id"],
                            rule["title"],
                            len(hits),
                        )
            except Exception as exc:
                logger.error("Sigma rule %s query failed: %s", rule["id"], exc)

    async def start(self):
        logger.info("Sigma worker started. Cycle interval: 3600s")
        while True:
            await self.run_cycle()
            await asyncio.sleep(3600)

    async def stop(self):
        await self.engine.dispose()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = SigmaWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
