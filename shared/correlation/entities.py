"""Entity extraction — pulls normalized entities from any alert.

Pure function, no LLM. Extracts users, hosts, IPs, cloud principals,
sessions, and devices. Normalises values (lowercased UPN, canonical IP,
stripped ARN).
"""

import hashlib
import logging

logger = logging.getLogger(__name__)

ENTITY_USER = "user"
ENTITY_HOST = "host"
ENTITY_IP = "ip"
ENTITY_PRINCIPAL = "principal"
ENTITY_SESSION = "session"
ENTITY_DEVICE = "device"

VALID_ENTITY_TYPES = {ENTITY_USER, ENTITY_HOST, ENTITY_IP, ENTITY_PRINCIPAL, ENTITY_SESSION, ENTITY_DEVICE}


class ExtractedEntity:
    """Lightweight entity descriptor — not a DB model."""

    def __init__(self, entity_type: str, value: str, role: str = "observed"):
        self.entity_type = entity_type
        self.value = value
        self.role = role

    def __repr__(self):
        return f"ExtractedEntity(type={self.entity_type}, value={self.value}, role={self.role})"


def _normalize(entity_type: str, raw: str) -> str:
    if not raw:
        return ""
    val = raw.strip()
    if entity_type == ENTITY_USER:
        val = val.lower()
    elif entity_type == ENTITY_IP:
        val = val.strip().rstrip(".").lstrip(".")
    elif entity_type == ENTITY_PRINCIPAL:
        val = val.strip()
    return val


def _dedup_key(entity_type: str, value: str) -> str:
    return hashlib.sha256(f"{entity_type}:{value}".encode()).hexdigest()


def extract_entities(alert) -> list[ExtractedEntity]:
    """Pull all identifiable entities from any alert (endpoint, identity, cloud, network, saas).

    Returns a list of ExtractedEntity with roles inferred from the alert context.
    """
    entities: list[ExtractedEntity] = []

    user = alert.user_name or getattr(alert, "source_user", None)
    if user:
        entities.append(ExtractedEntity(ENTITY_USER, _normalize(ENTITY_USER, user), "actor"))

    principal = getattr(alert, "principal", None)
    if principal:
        entities.append(ExtractedEntity(ENTITY_PRINCIPAL, _normalize(ENTITY_PRINCIPAL, principal), "actor"))

    if alert.agent_name:
        entities.append(ExtractedEntity(ENTITY_HOST, alert.agent_name.strip(), "source"))

    if alert.agent_ip:
        entities.append(ExtractedEntity(ENTITY_IP, alert.agent_ip.strip(), "source"))

    if alert.source_ip and (not alert.agent_ip or alert.source_ip != alert.agent_ip):
        entities.append(ExtractedEntity(ENTITY_IP, alert.source_ip.strip(), "actor"))

    if alert.destination_ip:
        entities.append(ExtractedEntity(ENTITY_IP, alert.destination_ip.strip(), "target"))

    dst_host = getattr(alert, "destination_host", None) or getattr(alert, "target_host", None)
    if dst_host:
        entities.append(ExtractedEntity(ENTITY_HOST, dst_host.strip(), "target"))

    session = getattr(alert, "session_id", None)
    if session:
        entities.append(ExtractedEntity(ENTITY_SESSION, session.strip(), "observed"))

    device_id = alert.agent_id or getattr(alert, "device_id", None)
    if device_id:
        entities.append(ExtractedEntity(ENTITY_DEVICE, device_id.strip(), "source"))

    seen = set()
    deduped = []
    for ent in entities:
        if not ent.value:
            continue
        key = _dedup_key(ent.entity_type, ent.value)
        if key not in seen:
            seen.add(key)
            deduped.append(ent)

    return deduped
