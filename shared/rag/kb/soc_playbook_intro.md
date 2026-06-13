# SOC Triage Playbook

## Initial Triage
- Verify alert severity using rule_level
- Check if source IP is in known bad IP lists
- Review MITRE ATT&CK mapping for context
- Look up past similar incidents

## Escalation Criteria
- Rule level >= 10: escalate to senior analyst
- Known malware indicator: escalate immediately
- Critical asset involved: prioritize over other alerts

## Containment Steps
- Isolate affected agent via Wazuh API
- Block source IP at firewall if lateral movement detected
- Collect full memory/disk forensic image
