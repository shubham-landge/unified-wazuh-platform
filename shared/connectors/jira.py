import logging

import httpx

from shared.config import settings
from shared.connectors.ticket_base import TicketConnector

logger = logging.getLogger(__name__)


class JiraConnector(TicketConnector):
    def __init__(self, url: str | None = None, email: str | None = None, api_token: str | None = None):
        self.url = (url or settings.jira_url).rstrip("/")
        self.email = email or settings.jira_email
        self.api_token = api_token or (
            settings.jira_api_token.get_secret_value() if settings.jira_api_token else ""
        )
        self.auth = (self.email, self.api_token)

    async def create_ticket(self, case_data: dict) -> dict:
        url = f"{self.url}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": case_data.get("project_key", "SOC")},
                "summary": case_data.get("title", ""),
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": case_data.get("description", ""),
                                }
                            ],
                        }
                    ],
                },
                "issuetype": {"name": "Task"},
                "priority": {"name": self._map_severity(case_data.get("severity", "low"))},
            }
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, json=payload, auth=self.auth)
            if resp.status_code == 201:
                data = resp.json()
                key = data.get("key", "")
                return {"remote_id": key, "remote_url": f"{self.url}/browse/{key}", "success": True}
            logger.error("Jira create failed: %d %s", resp.status_code, resp.text)
            return {"success": False, "error": resp.text}
        except Exception as exc:
            logger.error("Jira create failed: %s", exc)
            return {"success": False, "error": str(exc)}

    async def update_ticket(self, remote_id: str, case_data: dict) -> dict:
        url = f"{self.url}/rest/api/3/issue/{remote_id}"
        payload = {
            "fields": {
                "summary": case_data.get("title", ""),
                "priority": {"name": self._map_severity(case_data.get("severity", "low"))},
            }
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.put(url, json=payload, auth=self.auth)
            if resp.status_code == 204:
                return {"success": True}
            logger.error("Jira update failed: %d %s", resp.status_code, resp.text)
            return {"success": False, "error": resp.text}
        except Exception as exc:
            logger.error("Jira update failed: %s", exc)
            return {"success": False, "error": str(exc)}

    async def get_ticket(self, remote_id: str) -> dict:
        url = f"{self.url}/rest/api/3/issue/{remote_id}"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(url, auth=self.auth)
            if resp.status_code == 200:
                return {"success": True, "ticket": resp.json()}
            return {"success": False, "error": resp.text}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    async def health(self) -> dict:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self.url}/rest/api/3/myself", auth=self.auth)
            return {"connected": resp.status_code == 200, "status_code": resp.status_code}
        except Exception as exc:
            return {"connected": False, "error": str(exc)}

    async def create_case_ticket(self, case_data: dict) -> dict:
        return await self.create_ticket(case_data)

    @staticmethod
    def _map_severity(severity: str) -> str:
        return {"low": "Low", "medium": "Medium", "high": "High", "critical": "Highest"}.get(severity, "Medium")
