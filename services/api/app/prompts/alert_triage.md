# Alert Triage Prompt
#
# Used when analyzing a single Wazuh alert for triage.

Analyze the following Wazuh alert and provide structured triage analysis.

Alert Rule: {rule_description}
Rule ID: {rule_id}
Rule Level: {rule_level}
Rule Groups: {rule_groups}
Agent: {agent_name} ({agent_ip})
Source IP: {source_ip}
Destination IP: {destination_ip}
User: {user_name}
Process: {process_name}
File: {file_name}
Hash: {file_hash}
Event ID: {event_id}
MITRE Tactic: {mitre_tactic}
MITRE Technique: {mitre_technique}
Alert Timestamp: {alert_timestamp}

Consider:
1. Is this likely a true positive or false positive?
2. What is the severity based on rule level, asset criticality, and context?
3. What evidence should the analyst collect?
4. What is the recommended next action?
5. Does this require escalation?

Output valid JSON.
