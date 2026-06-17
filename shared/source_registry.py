from typing import Any, Dict, List

DATA_SOURCES = [
    {"id": "endpoint_logs", "name": "Endpoint Logs (Wazuh Agents)", "zone": "endpoint", "connected": True, "tactics": ["TA0001", "TA0002", "TA0003", "TA0004", "TA0005"]},
    {"id": "entra_id", "name": "Entra ID Audit & Sign-in Logs", "zone": "identity", "connected": True, "tactics": ["TA0001", "TA0003", "TA0004", "TA0006", "TA0008"]},
    {"id": "office_365", "name": "Office 365 / Exchange Logs", "zone": "saas", "connected": False, "tactics": ["TA0001", "TA0009"]},
    {"id": "aws_cloudtrail", "name": "AWS CloudTrail logs", "zone": "cloud", "connected": True, "tactics": ["TA0001", "TA0003", "TA0005", "TA0007", "TA0010"]},
    {"id": "network_firewall", "name": "Network Firewall Logs", "zone": "network", "connected": False, "tactics": ["TA0011"]},
    {"id": "email_gateway", "name": "Email Protection Logs", "zone": "email", "connected": False, "tactics": ["TA0001"]},
    {"id": "dns_logs", "name": "DNS Query Logs", "zone": "dns", "connected": False, "tactics": ["TA0007"]},
    {"id": "github_logs", "name": "GitHub Repository Logs", "zone": "code", "connected": False, "tactics": ["TA0001", "TA0002"]},
    {"id": "slack_audit", "name": "Slack Audit Logs", "zone": "comms", "connected": False, "tactics": ["TA0001"]},
    {"id": "llm_gateway", "name": "LLM Gateway Logs", "zone": "ai", "connected": False, "tactics": ["TA0010", "TA0011"]}
]

def get_registered_sources() -> List[Dict[str, Any]]:
    return DATA_SOURCES

def get_mitre_coverage() -> Dict[str, List[str]]:
    coverage = {}
    for ds in DATA_SOURCES:
        if ds["connected"]:
            for tactic in ds["tactics"]:
                coverage.setdefault(tactic, []).append(ds["name"])
    return coverage
