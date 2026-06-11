# False Positive Review Prompt
#
# Used when classifying whether an alert is likely a false positive.

Review this Wazuh alert for false positive indicators.

Alert Rule: {rule_description}
Rule Level: {rule_level}
Rule Groups: {rule_groups}
Agent Group: {agent_group}
Agent OS: {agent_os}
Source IP (internal/external): {source_ip_type}
User: {user_name}
Process: {process_name}
Event Count (24h): {event_count}

## Common False Positive Indicators
- Known administrative activity
- Approved scanning/assessment tools
- Legacy systems with expected behavior
- Misconfigured rules (too broad)
- Expected user behavior (password changes, group membership changes)
- Known application behavior

## Common True Positive Indicators
- Never-before-seen source IP/user
- Activity outside business hours
- Known-bad indicators (hashes, IPs, domains)
- Correlation with other alerts
- Deviation from baseline

Score the likelihood of false positive (0.0 = certain true positive, 1.0 = certain false positive).
Provide reasoning.
