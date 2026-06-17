from typing import Any, Dict, List

import os

from shared.config import settings

DATA_SOURCES = [
    {"id": "endpoint_logs", "name": "Endpoint Logs (Wazuh Agents)", "zone": "endpoint", "tactics": ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005"]},
    {"id": "entra_id", "name": "Entra ID Audit & Sign-in Logs", "zone": "identity", "tactics": ["TA0001", "TA0003", "TA0004", "TA0006", "TA0008"]},
    {"id": "office_365", "name": "Office 365 / Exchange Logs", "zone": "saas", "tactics": ["TA0001", "TA0009"]},
    {"id": "aws_cloudtrail", "name": "AWS CloudTrail logs", "zone": "cloud", "tactics": ["TA0001", "TA0003", "TA0005", "TA0007", "TA0010"]},
    {"id": "network_firewall", "name": "Network Firewall Logs", "zone": "network", "tactics": ["TA0011"]},
    {"id": "email_gateway", "name": "Email Protection Logs", "zone": "email", "tactics": ["TA0001"]},
    {"id": "dns_logs", "name": "DNS Query Logs", "zone": "dns", "tactics": ["TA0007"]},
    {"id": "github_logs", "name": "GitHub Repository Logs", "zone": "code", "tactics": ["TA0001", "TA0002"]},
    {"id": "slack_audit", "name": "Slack Audit Logs", "zone": "comms", "tactics": ["TA0001"]},
    {"id": "llm_gateway", "name": "LLM Gateway Logs", "zone": "ai", "tactics": ["TA0010", "TA0011"]},
]


def _is_connector_configured(source_id: str) -> bool:
    checks = {
        "entra_id": lambda: bool(os.getenv("ENTRA_TENANT_ID") or settings.oidc_client_id),
        "aws_cloudtrail": lambda: bool(os.getenv("AWS_ACCESS_KEY_ID")),
    }
    return checks.get(source_id, lambda: False)()


def get_registered_sources() -> List[Dict[str, Any]]:
    sources = []
    for ds in DATA_SOURCES:
        entry = dict(ds)
        entry["connected"] = _is_connector_configured(ds["id"])
        sources.append(entry)
    return sources


def get_mitre_coverage() -> Dict[str, List[str]]:
    coverage: Dict[str, List[str]] = {}
    for ds in get_registered_sources():
        if ds["connected"]:
            for tactic in ds.get("tactics", []):
                coverage.setdefault(tactic, []).append(ds["name"])
    return coverage
