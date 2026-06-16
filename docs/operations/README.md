# SOC Operations — Payless / Unified Wazuh Platform

Day-2 operations: runbooks, backups, monitoring, dashboards, and integration
health for running the SOC. Pair with the automation scripts in
[`../../scripts/`](../../scripts/).

## Documents

| Doc | Covers |
|---|---|
| [RUNBOOKS.md](RUNBOOKS.md) | Agent enrollment troubleshooting · clean reinstall · password rotation · emergency stop |
| [BACKUP-RESTORE.md](BACKUP-RESTORE.md) | What to back up (ossec.conf, client.keys, rules/decoders/lists, authd.pass, integrations, Filebeat, certs) · indexer snapshot/retention · restore · manager & dashboard rebuild |
| [MONITORING-RULES.md](MONITORING-RULES.md) | Critical rules to monitor (invalid password, duplicate agent, key-in-use, invalid ID, agent disconnected/never-connected, queue flooded, manager/indexer/filebeat errors) · severity routing · noisy-rule tuning |
| [DASHBOARDS.md](DASHBOARDS.md) | Payless overview · L1 triage · MITRE · endpoint health · enrollment failure · critical server · retail endpoint · weekly coverage |
| [INTEGRATIONS-HEALTH.md](INTEGRATIONS-HEALTH.md) | Indexer/Filebeat/syslog · Microsoft Graph/Azure/O365 · AWS CloudTrail · Teams/webhook · secure secret handling |

## Scripts

| Script | Purpose | Schedule |
|---|---|---|
| [`daily-health-check.sh`](../../scripts/daily-health-check.sh) | Manager daemons, queue, indexer, Filebeat, agents, platform services | daily 06:00 |
| [`weekly-capacity-report.sh`](../../scripts/weekly-capacity-report.sh) | Fleet, EPS, noisy rules, storage, disk runway, throughput | Mon 07:00 |
| [`wazuh-config-backup.sh`](../../scripts/wazuh-config-backup.sh) | Wazuh config + encrypted secrets (client.keys, authd.pass, certs) | daily 02:30 |
| [`../../deploy/backup.sh`](../../deploy/backup.sh) | Platform PostgreSQL dump | daily |

## Suggested cron

```cron
30 2 * * *  /opt/soc-platform/scripts/wazuh-config-backup.sh   >> /var/log/wazuh-backup.log 2>&1
0  6 * * *  /opt/soc-platform/scripts/daily-health-check.sh    >> /var/log/soc-health.log  2>&1
0  7 * * 1  /opt/soc-platform/scripts/weekly-capacity-report.sh > /var/log/soc-capacity-$(date +\%Y\%m\%d).txt 2>&1
```
