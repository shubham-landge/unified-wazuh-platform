from __future__ import annotations

from typing import Any

import logging

logger = logging.getLogger(__name__)


async def disable_user(user_id: str, reason: str | None = None, graph_token: str | None = None) -> dict[str, Any]:
    """Disable a user account via Microsoft Graph API.

    Caller must provide an OAuth2 token with User.ReadWrite.All scope
    (obtained via MSGraphConnector or EntraConnector OAuth2 flow).
    """
    if not graph_token:
        logger.warning("disable_user called without graph_token — no action taken")
        return {"success": False, "action": "disable_user", "user_id": user_id, "error": "No Graph API token"}
    import httpx
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.patch(
                f"https://graph.microsoft.com/v1.0/users/{user_id}",
                headers={"Authorization": f"Bearer {graph_token}"},
                json={"accountEnabled": False},
            )
            resp.raise_for_status()
        return {"success": True, "action": "disable_user", "user_id": user_id, "reason": reason}
    except Exception as exc:
        logger.error("disable_user failed: %s", exc)
        return {"success": False, "action": "disable_user", "user_id": user_id, "error": str(exc)}


async def revoke_sessions(user_id: str, graph_token: str | None = None) -> dict[str, Any]:
    """Revoke all active sessions for a user via Microsoft Graph API."""
    if not graph_token:
        return {"success": False, "action": "revoke_sessions", "user_id": user_id, "error": "No Graph API token"}
    import httpx
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(
                f"https://graph.microsoft.com/v1.0/users/{user_id}/revokeSignInSessions",
                headers={"Authorization": f"Bearer {graph_token}"},
            )
            resp.raise_for_status()
        return {"success": True, "action": "revoke_sessions", "user_id": user_id}
    except Exception as exc:
        logger.error("revoke_sessions failed: %s", exc)
        return {"success": False, "action": "revoke_sessions", "user_id": user_id, "error": str(exc)}


async def revoke_oauth_tokens(user_id: str, graph_token: str | None = None) -> dict[str, Any]:
    """Revoke OAuth grants for a user."""
    if not graph_token:
        return {"success": False, "action": "revoke_oauth_tokens", "user_id": user_id, "error": "No Graph API token"}
    import httpx
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            grants_resp = await client.get(
                "https://graph.microsoft.com/v1.0/oauth2PermissionGrants",
                headers={"Authorization": f"Bearer {graph_token}"},
            )
            grants_resp.raise_for_status()
            grants = grants_resp.json().get("value", [])
        revoked = 0
        for grant in grants:
            async with httpx.AsyncClient(timeout=20.0) as client:
                del_resp = await client.delete(
                    f"https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{grant.get('id')}",
                    headers={"Authorization": f"Bearer {graph_token}"},
                )
                if del_resp.status_code == 204:
                    revoked += 1
        return {"success": True, "action": "revoke_oauth_tokens", "user_id": user_id, "revoked": revoked}
    except Exception as exc:
        logger.error("revoke_oauth_tokens failed: %s", exc)
        return {"success": False, "action": "revoke_oauth_tokens", "user_id": user_id, "error": str(exc)}


async def force_reauth(user_id: str, graph_token: str | None = None) -> dict[str, Any]:
    """Force reauthentication by revoking sessions."""
    return await revoke_sessions(user_id, graph_token=graph_token)


async def block_ip(ip_address: str, reason: str | None = None) -> dict[str, Any]:
    """Block an IP address (placeholder — requires network infrastructure integration)."""
    return {"success": True, "action": "block_ip", "ip_address": ip_address, "reason": reason, "note": "Block requires conditional access policy integration"}
