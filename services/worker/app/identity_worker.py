import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shared.config import settings
from shared.connectors.cloudtrail import CloudTrailConnector
from shared.connectors.entra import EntraConnector
from shared.connectors.msgraph import MSGraphConnector
from shared.connectors.o365 import O365Connector
from shared.models.alert import Alert

logger = logging.getLogger(__name__)


@dataclass
class IdentityEvent:
    source_type: str
    event_type: str
    user: str | None = None
    principal: str | None = None
    session_id: str | None = None
    source_ip: str | None = None
    severity: str = "medium"
    rule_level: int = 7
    description: str = ""
    raw: dict | None = None
    event_time: datetime | None = None


class IdentityWorker:
    def __init__(
        self,
        interval_seconds: int = 300,
        session_factory=None,
        entra: EntraConnector | None = None,
        o365: O365Connector | None = None,
        msgraph: MSGraphConnector | None = None,
        cloudtrail: CloudTrailConnector | None = None,
    ):
        self.interval_seconds = interval_seconds
        self.engine = None
        if session_factory is None:
            self.engine = create_async_engine(settings.database_url, pool_size=2)
            self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)
        else:
            self.session_factory = session_factory
        self.entra = entra
        self.o365 = o365
        self.msgraph = msgraph
        self.cloudtrail = cloudtrail
        self._stopped = asyncio.Event()
        self.tenant_id = self._resolve_tenant_id()

    @staticmethod
    def _resolve_tenant_id() -> uuid.UUID:
        try:
            return uuid.UUID(settings.tenant_id)
        except Exception:
            return uuid.UUID("00000000-0000-0000-0000-000000000001")

    def _session_context(self):
        factory = self.session_factory
        if hasattr(factory, "__aenter__") and hasattr(factory, "__aexit__"):
            return factory
        return factory()

    async def start(self):
        while not self._stopped.is_set():
            try:
                await self.scan_once()
            except Exception as exc:
                logger.error("Identity worker scan failed: %s", exc, exc_info=True)
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=self.interval_seconds)
            except asyncio.TimeoutError:
                pass

    async def stop(self):
        self._stopped.set()
        if self.engine:
            await self.engine.dispose()

    async def scan_once(self) -> dict:
        events = await self._collect_events()
        created = 0
        async with self._session_context() as session:
            for event in events:
                if await self._persist_alert(session, event):
                    created += 1
            await session.commit()
        return {"success": True, "created": created}

    async def _collect_events(self) -> list[IdentityEvent]:
        events: list[IdentityEvent] = []
        if self.entra:
            signins = await self.entra.get_signins()
            audits = await self.entra.get_audit_logs()
            events.extend(self._from_entra_signins(signins))
            events.extend(self._from_entra_audits(audits))
        if self.o365:
            events.extend(self._from_o365(await self.o365.get_audit_logs()))
        if self.msgraph:
            risky_signins = await self.msgraph.get_risky_signins()
            risky_users = await self.msgraph.get_risky_users()
            oauth = await self.msgraph.get_oauth_grants()
            events.extend(self._from_msgraph(risky_signins, risky_users, oauth))
        if self.cloudtrail:
            events.extend(self._from_cloudtrail(await self.cloudtrail.get_events()))
        return events

    def _from_entra_signins(self, records: list[dict]) -> list[IdentityEvent]:
        events: list[IdentityEvent] = []
        for record in records:
            user = self._lower(record.get("userPrincipalName") or record.get("user"))
            risk = str(record.get("riskLevelAggregated") or record.get("riskLevel") or "").lower()
            mfa = record.get("authenticationMethodsUsed") or []
            attempts = record.get("mfaAttempts") or record.get("mfa_attempts") or 0
            ip = record.get("ipAddress") or record.get("ip")
            if record.get("isImpossibleTravel") or "impossible" in str(record.get("riskDetail", "")).lower():
                events.append(self._event("identity", "impossible_travel", user=user, source_ip=ip, severity="high", rule_level=10, raw=record))
            if attempts and int(attempts) >= 3:
                events.append(self._event("identity", "mfa_fatigue", user=user, source_ip=ip, severity="high", rule_level=10, raw=record))
            if risk in {"high", "medium"}:
                events.append(self._event("identity", "risky_signin", user=user, source_ip=ip, severity="high", rule_level=10, raw=record))
            if len(mfa) > 0 and record.get("status") == "failure":
                events.append(self._event("identity", "mfa_fatigue", user=user, source_ip=ip, severity="medium", rule_level=7, raw=record))
        return events

    def _from_entra_audits(self, records: list[dict]) -> list[IdentityEvent]:
        events: list[IdentityEvent] = []
        for record in records:
            user = self._lower(record.get("initiatedBy", {}).get("user", {}).get("userPrincipalName") if isinstance(record.get("initiatedBy"), dict) else record.get("user"))
            activity = str(record.get("activityDisplayName") or record.get("operationName") or "").lower()
            if "role" in activity or "privileged" in activity:
                events.append(self._event("identity", "privilege_change", user=user, severity="high", rule_level=10, raw=record))
            if "reset password" in activity and "mfa" in activity:
                events.append(self._event("identity", "helpdesk_impersonation", user=user, severity="high", rule_level=10, raw=record))
            if "consent" in activity and "oauth" in activity:
                events.append(self._event("identity", "illicit_oauth_consent", user=user, severity="critical", rule_level=12, raw=record))
        return events

    def _from_o365(self, records: list[dict]) -> list[IdentityEvent]:
        events: list[IdentityEvent] = []
        for record in records:
            activity = str(record.get("activity") or record.get("operation") or "").lower()
            user = self._lower(record.get("user") or record.get("userPrincipalName"))
            if "consent" in activity and "oauth" in activity:
                events.append(self._event("identity", "illicit_oauth_consent", user=user, severity="critical", rule_level=12, raw=record))
            if "reset" in activity and "mfa" in activity:
                events.append(self._event("identity", "helpdesk_impersonation", user=user, severity="high", rule_level=10, raw=record))
            if "privilege" in activity or "role" in activity:
                events.append(self._event("identity", "privilege_change", user=user, severity="high", rule_level=10, raw=record))
        return events

    def _from_msgraph(self, risky_signins: list[dict], risky_users: list[dict], oauth: list[dict]) -> list[IdentityEvent]:
        events: list[IdentityEvent] = []
        for record in risky_signins:
            user = self._lower(record.get("userPrincipalName") or record.get("user"))
            risk = str(record.get("riskLevel") or record.get("riskState") or "").lower()
            if "impossible" in str(record.get("riskDetail", "")).lower():
                events.append(self._event("identity", "impossible_travel", user=user, source_ip=record.get("ipAddress"), severity="high", rule_level=10, raw=record))
            if risk in {"high", "medium"}:
                events.append(self._event("identity", "risky_signin", user=user, source_ip=record.get("ipAddress"), severity="high", rule_level=10, raw=record))
        for record in risky_users:
            user = self._lower(record.get("userPrincipalName") or record.get("user"))
            if str(record.get("riskLevel") or "").lower() in {"high", "medium"}:
                events.append(self._event("identity", "risky_signin", user=user, severity="high", rule_level=10, raw=record))
        for record in oauth:
            user = self._lower(record.get("principalDisplayName") or record.get("user"))
            if str(record.get("consentType") or "").lower() in {"allprincipals", "tenant"}:
                events.append(self._event("identity", "illicit_oauth_consent", user=user, severity="critical", rule_level=12, raw=record))
        return events

    def _from_cloudtrail(self, records: list[dict]) -> list[IdentityEvent]:
        events: list[IdentityEvent] = []
        for record in records:
            event_name = str(record.get("eventName") or record.get("event") or "").lower()
            user = self._lower(record.get("userIdentity", {}).get("userName") if isinstance(record.get("userIdentity"), dict) else record.get("user"))
            principal = None
            if isinstance(record.get("userIdentity"), dict):
                principal = record["userIdentity"].get("arn")
            if "iam" in event_name and ("attach" in event_name or "policy" in event_name or "role" in event_name):
                events.append(self._event("cloud", "privilege_change", user=user, principal=principal, severity="high", rule_level=10, raw=record))
            if "consolelogin" in event_name and "failure" in str(record.get("errorMessage", "")).lower():
                events.append(self._event("cloud", "risky_signin", user=user, principal=principal, severity="medium", rule_level=7, raw=record))
        return events

    async def _persist_alert(self, session, event: IdentityEvent) -> bool:
        alert = Alert(
            tenant_id=self.tenant_id,
            wazuh_alert_id=f"identity:{event.event_type}:{uuid.uuid4()}",
            rule_id=None,
            rule_description=event.description or event.event_type.replace("_", " ").title(),
            rule_level=event.rule_level,
            rule_groups=["identity", event.event_type],
            user_name=event.user,
            event_type="identity",
            event_action=event.event_type,
            log_source="identity-worker",
            raw_alert_redacted={
                "source_type": event.source_type,
                "principal": event.principal,
                "session_id": event.session_id,
                "raw": event.raw or {},
            },
            alert_timestamp=event.event_time or datetime.now(timezone.utc),
            ingested_at=datetime.now(timezone.utc),
            created_at=datetime.now(timezone.utc),
        )
        session.add(alert)
        return True

    @staticmethod
    def _event(source_type: str, event_type: str, **kwargs) -> IdentityEvent:
        return IdentityEvent(source_type=source_type, event_type=event_type, **kwargs)

    @staticmethod
    def _lower(value: str | None) -> str | None:
        return value.lower() if isinstance(value, str) else value


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    worker = IdentityWorker()
    try:
        await worker.start()
    except KeyboardInterrupt:
        await worker.stop()


if __name__ == "__main__":
    asyncio.run(main())
