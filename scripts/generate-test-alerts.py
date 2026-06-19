#!/usr/bin/env python3
"""Generate test alerts in the SOC DB to simulate real traffic.

Usage: python3 scripts/generate-test-alerts.py [--count N]

Creates alert records directly in PostgreSQL (via the API) rather than
going through Wazuh, so it works without a running Wazuh environment.
"""

import argparse
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

ALERT_TEMPLATES = [
    {"rule_id": 80101, "rule_level": 10, "rule_description": "Windows Defender real-time threat detected", "mitre_tactic": "TA0002", "mitre_technique": "T1204"},
    {"rule_id": 5710, "rule_level": 12, "rule_description": "SSH Brute Force Attack", "mitre_tactic": "TA0006", "mitre_technique": "T1110"},
    {"rule_id": 92200, "rule_level": 7, "rule_description": "Windows Error: Application Crash", "mitre_tactic": "", "mitre_technique": ""},
    {"rule_id": 80702, "rule_level": 8, "rule_description": "Windows Defender scan completed", "mitre_tactic": "", "mitre_technique": ""},
    {"rule_id": 55006, "rule_level": 15, "rule_description": "Possible webshell detected", "mitre_tactic": "TA0003", "mitre_technique": "T1505.003"},
    {"rule_id": 31163, "rule_level": 14, "rule_description": "Ransomware file extension detected", "mitre_tactic": "TA0040", "mitre_technique": "T1486"},
    {"rule_id": 18104, "rule_level": 9, "rule_description": "Windows audit log cleared", "mitre_tactic": "TA0005", "mitre_technique": "T1070.001"},
    {"rule_id": 61650, "rule_level": 11, "rule_description": "User account added to privileged group", "mitre_tactic": "TA0003", "mitre_technique": "T1098"},
    {"rule_id": 86001, "rule_level": 6, "rule_description": "DNS query to known malicious domain", "mitre_tactic": "TA0011", "mitre_technique": "T1568"},
    {"rule_id": 50201, "rule_level": 7, "rule_description": "Sysmon process creation event", "mitre_tactic": "", "mitre_technique": ""},
]

AGENTS = [
    {"name": "server-web-01", "ip": "10.0.1.10", "id": "agent-001"},
    {"name": "server-db-01", "ip": "10.0.1.20", "id": "agent-002"},
    {"name": "laptop-admin", "ip": "10.0.2.5", "id": "agent-003"},
    {"name": "workstation-dev", "ip": "10.0.2.15", "id": "agent-004"},
    {"name": "server-app-01", "ip": "10.0.3.10", "id": "agent-005"},
]

USERS = ["alice@company.com", "bob@company.com", "admin@company.com", "charlie@company.com", ""]

SOURCES = ["192.168.1.100", "10.0.0.1", "203.0.113.5", "198.51.100.20", ""]
DESTS = ["10.0.1.10", "10.0.1.20", "10.0.2.1", "0.0.0.0"]

TENANT_ID = "00000000-0000-0000-0000-000000000001"


def generate_alerts(count: int) -> list[dict]:
    alerts = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=24)
    for i in range(count):
        template = random.choice(ALERT_TEMPLATES)
        agent = random.choice(AGENTS)
        user = random.choice(USERS)
        src = random.choice(SOURCES)
        dst = random.choice(DESTS)
        alert = {
            "tenant_id": TENANT_ID,
            "wazuh_alert_id": f"test-{uuid.uuid4().hex[:12]}",
            "rule_id": template["rule_id"],
            "rule_description": template["rule_description"],
            "rule_level": template["rule_level"],
            "rule_groups": ["test", "simulation"],
            "mitre_tactic": template["mitre_tactic"],
            "mitre_technique": template["mitre_technique"],
            "agent_id": agent["id"],
            "agent_name": agent["name"],
            "agent_ip": agent["ip"],
            "source_ip": src if src else agent["ip"],
            "destination_ip": dst,
            "user_name": user if user else "",
            "source_type": random.choice(["endpoint", "endpoint", "endpoint", "identity", "network"]),
            "alert_timestamp": (base_time + timedelta(minutes=i * 2)).isoformat(),
            "raw_alert_redacted": {"test": True},
        }
        alerts.append(alert)
    return alerts


def main():
    parser = argparse.ArgumentParser(description="Generate test alerts for SOC simulation")
    parser.add_argument("--count", type=int, default=50, help="Number of alerts to generate")
    parser.add_argument("--output", type=str, default="", help="Output file (JSON); default: print to stdout")
    args = parser.parse_args()

    alerts = generate_alerts(args.count)
    output = json.dumps(alerts, indent=2, default=str)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Generated {len(alerts)} alerts → {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
