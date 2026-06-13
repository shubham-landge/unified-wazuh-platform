import httpx
import logging
from shared.config import settings
from shared.connectors.ticket_base import TicketConnector

logger = logging.getLogger(__name__)


class ServiceNowConnector(TicketConnector):
    def __init__(self, instance: str | None = None, user: str | None = None, password: str | None = None):
        self.instance = instance or settings.servicenow_instance
        self.user = user or settings.servicenow_user
        self.password = password or settings.servicenow_password.get_secret_value() if settings.servicenow_password else ""

    async def create_ticket(self, case_data: dict) -> dict:
        url = f"https://{self.instance}.service-now.com/api/now/table/incident"
        auth = (self.user, self.password)
        payload = {
            "short_description": case_data.get("title", ""),
            "description": case_data.get("description", ""),
            "severity": self._map_severity(case_data.get("severity", "low")),
            "assignment_group": case_data.get("assigned_to", ""),
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, json=payload, auth=auth)
            if resp.status_code == 201:
                data = resp.json().get("result", {})
                return {"remote_id": data.get("sys_id", ""), "remote_url": f"{url}/{data.get('sys_id', '')}", "success": True}
            logger.error("ServiceNow create failed: %d %s", resp.status_code, resp.text)
            return {"success": False, "error": resp.text}

    async def update_ticket(self, remote_id: str, case_data: dict) -> dict:
        url = f"https://{self.instance}.service-now.com/api/now/table/incident/{remote_id}"
        auth = (self.user, self.password)
        payload = {
            "short_description": case_data.get("title", ""),
            "description": case_data.get("description", ""),
            "severity": self._map_severity(case_data.get("severity", "low")),
            "state": self._map_status(case_data.get("status", "open")),
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.patch(url, json=payload, auth=auth)
            if resp.status_code == 200:
                return {"success": True}
            logger.error("ServiceNow update failed: %d %s", resp.status_code, resp.text)
            return {"success": False, "error": resp.text}

    async def get_ticket(self, remote_id: str) -> dict:
        url = f"https://{self.instance}.service-now.com/api/now/table/incident/{remote_id}"
        auth = (self.user, self.password)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, auth=auth)
            if resp.status_code == 200:
                return {"success": True, "ticket": resp.json().get("result", {})}
            return {"success": False, "error": resp.text}

    async def health(self) -> dict:
        url = f"https://{self.instance}.service-now.com/api/now/table/incident?sysparm_limit=1"
        auth = (self.user, self.password)
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(url, auth=auth)
                return {"connected": resp.status_code == 200, "status_code": resp.status_code}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    @staticmethod
    def _map_severity(severity: str) -> int:
        return {"low": 4, "medium": 3, "high": 2, "critical": 1}.get(severity, 3)

    @staticmethod
    def _map_status(status: str) -> int:
        return {"open": 1, "in_progress": 2, "resolved": 6, "closed": 7}.get(status, 1)
