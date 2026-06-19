"""Deterministic SHA-256 fingerprint for meta-alert grouping.

Provides a fast exact-match dedup pass that complements AECID aggregation.
Partial mode selects a subset of fields; full mode serialises all non-null fields.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# Sentinel for missing values that should still contribute to the fingerprint.
_MISSING = object()


def compute_fingerprint(
    alert: dict[str, Any] | Any,
    fields: list[str] | None = None,
    mode: str = "partial",
) -> str:
    """Return a SHA-256 hex digest uniquely identifying *alert*.

    Parameters
    ----------
    alert:
        A dict-like object (plain dict, ORM model, dataclass, …) to fingerprint.
    fields:
        Field names to include in partial mode.  Ignored in full mode.
    mode:
        ``"partial"`` — only the keys listed in *fields* contribute.
        ``"full"``   — every non-None attribute contributes.

    Returns
    -------
    A 64-character hexadecimal SHA-256 digest.
    """
    if mode == "full":
        # Extract every non-None, non-internal attribute.
        raw = _extract_all(alert)
    elif mode == "partial":
        fields = fields or []
        raw = {f: _get_field(alert, f) for f in fields}
    else:
        msg = f"Unknown fingerprint mode: {mode!r} (expected 'partial' or 'full')"
        raise ValueError(msg)

    # Stable serialisation: sorted keys + ``default=str`` so UUIDs / datetimes
    # never cause a ``TypeError``.
    serialised = json.dumps(raw, sort_keys=True, default=str)
    return hashlib.sha256(serialised.encode()).hexdigest()


def get_default_fingerprint_fields(source: str = "wazuh") -> list[str]:
    """Return sensible default field names for *source*.

    These fields capture the most dedup-relevant dimensions for each
    data-source type.  Callers may override via database-level configuration.
    """
    _defaults: dict[str, list[str]] = {
        "wazuh": ["rule_id", "source_ip", "agent_id"],
        "entra_id": ["event_id", "user_name", "source_ip"],
        "aws_cloudtrail": ["event_name", "source_ip", "user_name"],
        "network_firewall": ["source_ip", "destination_ip", "destination_port", "protocol"],
        "office_365": ["event_id", "user_name", "source_ip"],
        "okta": ["event_id", "source_ip", "user_name"],
        "gcp_audit": ["event_type", "principal", "source_ip"],
    }
    return _defaults.get(source, ["rule_id", "source_ip"])


# ── internal helpers ─────────────────────────────────────────────────────────

def _extract_all(alert: dict[str, Any] | Any) -> dict[str, Any]:
    """Return every public, non-None attribute of *alert*."""
    if isinstance(alert, dict):
        return {k: v for k, v in alert.items() if v is not None and not k.startswith("_")}
    # ORM model, dataclass, or other object — use __dict__ / vars()
    data: dict[str, Any] = {}
    for key, value in (vars(alert).items() if hasattr(alert, "__dict__") else {}):
        if key.startswith("_") or value is None:
            continue
        data[key] = value
    # Include SQLAlchemy instrumented attributes that may not be in __dict__
    # when loaded from DB (e.g. ``alert.rule_id`` but not ``alert.__dict__["rule_id"]``).
    if hasattr(alert, "_sa_instance_state"):
        for col in getattr(alert, "__table__", {}).columns:  # type: ignore[union-attr]
            if col.name not in data:
                v = getattr(alert, col.name, _MISSING)
                if v is not _MISSING and v is not None:
                    data[col.name] = v
    return data


def _get_field(alert: dict[str, Any] | Any, name: str) -> Any:
    """Safely extract a single field from a dict or object."""
    if isinstance(alert, dict):
        return alert.get(name)
    return getattr(alert, name, None)
