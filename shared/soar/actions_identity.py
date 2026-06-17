from __future__ import annotations

from typing import Any


async def disable_user(user_id: str, reason: str | None = None) -> dict[str, Any]:
    return {"success": True, "action": "disable_user", "user_id": user_id, "reason": reason}


async def revoke_sessions(user_id: str) -> dict[str, Any]:
    return {"success": True, "action": "revoke_sessions", "user_id": user_id}


async def revoke_oauth_tokens(user_id: str) -> dict[str, Any]:
    return {"success": True, "action": "revoke_oauth_tokens", "user_id": user_id}


async def force_reauth(user_id: str) -> dict[str, Any]:
    return {"success": True, "action": "force_reauth", "user_id": user_id}


async def block_ip(ip_address: str, reason: str | None = None) -> dict[str, Any]:
    return {"success": True, "action": "block_ip", "ip_address": ip_address, "reason": reason}
