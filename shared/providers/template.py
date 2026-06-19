import logging
from typing import Any

from pydantic import BaseModel, Field

from shared.providers.base import BaseProvider

logger = logging.getLogger(__name__)


class TemplateConfig(BaseModel):
    """Example CONFIG_SCHEMA for the template provider."""

    api_url: str = Field(..., min_length=1, description="Base URL for the API")
    api_key: str = Field(default="", description="Authentication token")
    timeout: int = Field(default=30, ge=1, le=300)


class TemplateProvider(BaseProvider):
    """Reference implementation showing the BaseProvider contract.

    Use this as a starting point when building new providers.
    """

    PROVIDER_TYPE = "template"
    SCOPES = ["read", "write"]
    FINGERPRINT_FIELDS = ["api_url"]
    CONFIG_SCHEMA = TemplateConfig

    def __init__(self, api_url: str = "", api_key: str = "", timeout: int = 30) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._webhook_secret: str | None = None

    # ── required ──────────────────────────────────────────────────────────

    def validate_config(self) -> None:
        if not self.api_url:
            raise ValueError("api_url is required")

    async def health(self) -> dict:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.api_url}/health")
                resp.raise_for_status()
            return {"connected": True, "api_url": self.api_url}
        except Exception as exc:
            return {"connected": False, "error": str(exc), "api_url": self.api_url}

    # ── optional capabilities ─────────────────────────────────────────────

    async def query(self, endpoint: str = "", **kwargs: Any) -> dict:
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        import httpx
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.api_url}/{endpoint.lstrip('/')}",
                headers=headers,
                params=kwargs,
            )
            resp.raise_for_status()
            return {"success": True, "data": resp.json()}

    async def notify(self, message: str, **kwargs: Any) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        import httpx
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.api_url}/notify",
                headers=headers,
                json={"message": message, **kwargs},
            )
            resp.raise_for_status()
            return {"success": True, "status_code": resp.status_code}

    async def get_webhook(self) -> dict | None:
        if not self._webhook_secret:
            return None
        return {
            "url": f"{self.api_url}/webhook",
            "secret": self._webhook_secret,
            "events": ["alert", "notification"],
        }

    def set_webhook_secret(self, secret: str) -> None:
        self._webhook_secret = secret
