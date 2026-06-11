# Investigation Steps Prompt
#
# Used when generating step-by-step investigation guidance for a security alert.

Generate a step-by-step investigation plan for the following security alert.

Alert: {alert_summary}
Category: {category}
Severity: {severity}
Key Entities: {key_entities}
MITRE Mapping: {mitre_mapping}

For each step, provide:
- What to check
- Where to look (Wazuh dashboard, Indexer query, agent logs, SIEM search)
- What finding indicates true positive
- What finding indicates false positive
- Safety note if applicable

Steps should be ordered by:
1. Immediate verification (last 5 minutes)
2. Short-term investigation (last hour)
3. Deep investigation (last 24 hours)
4. Containment recommendations (if confirmed)
5. Recovery recommendations (if applicable)

Never recommend destructive actions without human approval.
