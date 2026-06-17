import logging
from time import perf_counter

import httpx

logger = logging.getLogger(__name__)

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
SCOPE = "https://graph.microsoft.com/.default"


class O365Connector:
    def __init__(self, tenant_id: str = "", client_id: str = "", client_secret: str = ""):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: str | None = None

    async def _acquire_token(self) -> str | None:
        if not self.client_id or not self.client_secret or not self.tenant_id:
            logger.warning("O365 connector not configured (tenant_id/client_id/client_secret required)")
            return None
        url = TOKEN_URL.format(tenant=self.tenant_id)
        data = {"client_id": self.client_id, "client_secret": self.client_secret, "scope": SCOPE, "grant_type": "client_credentials"}
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, data=data)
                resp.raise_for_status()
                self._token = resp.json()["access_token"]
            return self._token
        except Exception as exc:
            logger.error("O365 token acquisition failed: %s", exc)
            return None

    async def _auth_headers(self) -> dict:
        if not self._token:
            self._token = await self._acquire_token()
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    async def get_audit_logs(self, limit: int = 100) -> list[dict]:
        headers = await self._auth_headers()
        if not headers:
            return []
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits",
                    headers=headers, params={"$top": limit}
                )
                resp.raise_for_status()
                data = resp.json()
            return data.get("value", []) if isinstance(data, dict) else []
        except Exception as exc:
            logger.error("O365 audit log fetch failed: %s", exc)
            return []

    async def health(self) -> dict:
        started = perf_counter()
        headers = await self._auth_headers()
        if not headers:
            return {"connected": False, "error": "O365 not configured", "latency_ms": 0}
        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get("https://graph.microsoft.com/v1.0/organization", headers=headers)
                resp.raise_for_status()
            return {"connected": True, "latency_ms": round((perf_counter() - started) * 1000)}
        except Exception as exc:
            logger.error("O365 health failed: %s", exc)
            return {"connected": False, "error": str(exc), "latency_ms": round((perf_counter() - started) * 1000)}
