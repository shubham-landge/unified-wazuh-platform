"""Semantic result cache for AI triage.

DEPRECATED: Use `shared.enrichment.semantic_cache.SemanticCache` directly.
            This module is kept for backward compatibility — ``lookup()`` and
            ``store()`` now delegate to ``SemanticCache`` internally.

Near-duplicate alerts reuse recent verdicts without paying the LLM inference
penalty.  The cache is keyed by normalized entities + rule_id and stored in
Redis with the verdict embedding and TTL.
"""

import json
import logging
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any

import redis.asyncio as redis

from shared.config import settings
from shared.enrichment.semantic_cache import SemanticCache
from shared.models.alert import Alert

logger = logging.getLogger(__name__)

_TRIAGE_CACHE_INDEX = "triage_cache_index"


def _normalize_entities(alert: Alert) -> dict[str, str]:
    """Return normalized fields that make a triage result reusable."""
    return {
        "rule_id": str(alert.rule_id or "").strip().lower(),
        "source_ip": str(alert.source_ip or "").strip().lower(),
        "agent_id": str(alert.agent_id or ""),
        "user_name": str(alert.user_name or "").strip().lower(),
        "process_name": str(alert.process_name or "").strip().lower(),
    }


def cache_key(alert: Alert) -> str:
    """Deterministic key for the cache bucket for this alert."""
    entities = _normalize_entities(alert)
    payload = json.dumps(entities, sort_keys=True)
    return f"triage_cache:{sha256(payload.encode()).hexdigest()[:32]}"


def _verdict_text(verdict: dict[str, Any]) -> str:
    """Flatten a triage verdict into an embeddable string."""
    parts = [
        verdict.get("summary", ""),
        verdict.get("category", ""),
        verdict.get("severity", ""),
        str(verdict.get("false_positive_likelihood", "")),
    ]
    return " | ".join(p for p in parts if p)


def _alert_to_features(alert: Alert) -> dict[str, str]:
    """Convert an Alert to the feature dict expected by ``SemanticCache``."""
    return {
        "rule_description": str(alert.rule_description or ""),
        "source_ip": str(alert.source_ip or ""),
        "mitre_technique": str(alert.mitre_technique or ""),
        "rule_groups": str(alert.rule_groups or ""),
    }


async def lookup(
    redis_client: redis.Redis | None,
    alert: Alert,
    threshold: float | None = None,
) -> dict[str, Any] | None:
    """Return a cached triage verdict if a semantically similar one exists.

    .. deprecated::
        Use ``SemanticCache.lookup()`` instead.  This function delegates to
        the new implementation and will be removed in a future release.
    """
    if not redis_client or not settings.triage_cache_enabled:
        return None
    if alert.rule_level and alert.rule_level >= settings.triage_cache_skip_level:
        return None

    threshold = threshold or settings.triage_cache_similarity_threshold
    tenant_id = str(alert.tenant_id) if alert.tenant_id else "default"

    cache = SemanticCache(redis_client=redis_client, tenant_id=tenant_id)
    alert_features = _alert_to_features(alert)
    hit, result = await cache.lookup(alert_features, threshold=threshold)

    if hit:
        result["_cached"] = True
        result["_cache_source"] = "semantic"
        logger.info(
            "Triage cache hit for alert %s (delegated to SemanticCache)",
            alert.id,
        )
        return result

    return None


async def store(
    redis_client: redis.Redis | None,
    alert: Alert,
    verdict: dict[str, Any],
) -> bool:
    """Store a triage verdict in the semantic cache.

    .. deprecated::
        Use ``SemanticCache.store()`` instead.  This function delegates to
        the new implementation and will be removed in a future release.
    """
    if not redis_client or not settings.triage_cache_enabled:
        return False
    if alert.rule_level and alert.rule_level >= settings.triage_cache_skip_level:
        return False

    tenant_id = str(alert.tenant_id) if alert.tenant_id else "default"
    cache = SemanticCache(redis_client=redis_client, tenant_id=tenant_id)
    alert_features = _alert_to_features(alert)
    return await cache.store(
        alert_features,
        verdict,
        ttl=settings.triage_cache_ttl_seconds,
    )
