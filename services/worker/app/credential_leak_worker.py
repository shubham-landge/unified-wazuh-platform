"""Credential leak monitoring worker — queries HIBP for breached emails/domains."""
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select

from shared.config import settings
from shared.models.credential_leak import CredentialLeak

logger = logging.getLogger(__name__)

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"


class CredentialLeakWorker:
    def __init__(self):
        self.engine = create_async_engine(settings.database_url, pool_size=2)
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    async def start(self):
        if not settings.credential_leak_monitor_enabled:
            logger.info("Credential leak monitoring is disabled.")
            return

        logger.info("Credential leak monitoring started.")
        while True:
            try:
                await self._check_all()
            except Exception as exc:
                logger.error("Credential leak check failed: %s", exc, exc_info=True)

            await asyncio.sleep(settings.credential_leak_check_interval_seconds)

    async def _check_all(self):
        emails = [e.strip() for e in settings.credential_leak_monitored_emails.split(",") if e.strip()]
        domains = [d.strip() for d in settings.credential_leak_monitored_domains.split(",") if d.strip()]

        if not emails and not domains:
            logger.debug("No monitored emails or domains configured.")
            return

        async with self.session_factory() as session:
            for email in emails:
                await self._check_email(session, email)
            for domain in domains:
                await self._check_domain(session, domain)
            await session.commit()

    async def _check_email(self, session, email: str):
        breaches = await self._query_hibp(f"breachedaccount/{email}")
        for breach in breaches:
            await self._upsert_leak(session, email, "email", breach)

    async def _check_domain(self, session, domain: str):
        breaches = await self._query_hibp(f"breacheddomain/{domain}")
        for breach in breaches:
            await self._upsert_leak(session, domain, "domain", breach)

    async def _query_hibp(self, path: str) -> list[dict]:
        api_key = (
            settings.credential_leak_hibp_api_key.get_secret_value()
            if settings.credential_leak_hibp_api_key
            else None
        )
        if not api_key:
            logger.warning("HIBP API key not configured; skipping credential leak check.")
            return []

        url = f"{HIBP_API_BASE}/{path}"
        headers = {
            "hibp-api-key": api_key,
            "User-Agent": "UnifiedWazuhSOC-CredentialLeakWorker",
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url, headers=headers)
                if response.status_code == 404:
                    return []
                response.raise_for_status()
                data = response.json()
                return data if isinstance(data, list) else [data]
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                return []
            logger.error("HIBP request failed for %s: %s", path, exc)
            return []
        except Exception as exc:
            logger.error("HIBP request failed for %s: %s", path, exc)
            return []

    async def _upsert_leak(self, session, target: str, target_type: str, breach: dict):
        breach_name = breach.get("Name") or breach.get("name")
        if not breach_name:
            return

        # Deduplicate by target + breach_name.
        existing = await session.execute(
            select(CredentialLeak).where(
                CredentialLeak.target == target,
                CredentialLeak.target_type == target_type,
                CredentialLeak.breach_name == breach_name,
            )
        )
        if existing.scalar_one_or_none():
            return

        leak = CredentialLeak(
            tenant_id=self._default_tenant_id(),
            target=target,
            target_type=target_type,
            breach_name=breach_name,
            breach_date=breach.get("BreachDate") or breach.get("breach_date"),
            compromised_data=breach.get("DataClasses") or breach.get("data_classes") or [],
            breach_description=breach.get("Description") or breach.get("description"),
            source="hibp",
            raw_data=breach,
        )
        session.add(leak)
        logger.info(
            "New credential leak detected: %s in breach '%s'", target, breach_name
        )

    @staticmethod
    def _default_tenant_id():
        try:
            return uuid.UUID(settings.tenant_id)
        except Exception:
            return uuid.UUID("00000000-0000-0000-0000-000000000001")

    async def stop(self):
        await self.engine.dispose()


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = CredentialLeakWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
