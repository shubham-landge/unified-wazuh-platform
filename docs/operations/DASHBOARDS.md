# Dashboard Catalog — Payless SOC

Build specs for the saved dashboards the SOC needs. Each entry lists the
**purpose**, **index pattern**, **key panels with the exact query/aggregation**,
and the **audience**. Export the finished set as `dashboards/payless-dashboards.ndjson`
(see [BACKUP-RESTORE.md §5](BACKUP-RESTORE.md#5-dashboard-rebuild-procedure)) so it's version-controlled.

> Index pattern: `wazuh-alerts-*` unless noted. Time field: `timestamp`.
> Build in Wazuh Dashboard (OpenSearch Dashboards) → Visualize → Dashboard, or
> import the NDJSON once authored.

---

## Catalog overview

| # | Dashboard | Audience | Refresh | Primary index |
|---|---|---|---|---|
| 1 | Payless Overview (exec) | SOC lead / Payless stakeholders | 5 min | `wazuh-alerts-*` |
| 2 | L1 Triage View | L1 analysts | 30 s | `wazuh-alerts-*` |
| 3 | MITRE ATT&CK View | L2 / threat hunt | 5 min | `wazuh-alerts-*` |
| 4 | Endpoint Health | SOC ops | 1 min | `wazuh-alerts-*` + agent status |
| 5 | Enrollment Failure | SOC ops | 1 min | `wazuh-alerts-*` (ops_health) |
| 6 | Critical Server | L2 / IR | 1 min | `wazuh-alerts-*` |
| 7 | Retail Endpoint (POS/store) | SOC ops | 5 min | `wazuh-alerts-*` |
| 8 | Weekly Coverage Report | SOC lead | scheduled | `wazuh-alerts-*` |

---

## 1. Payless Overview (Executive)

**Purpose:** one-screen security posture for leadership. **Audience:** SOC lead, Payless.

| Panel | Type | Query / aggregation |
|---|---|---|
| Total alerts (24h) | Metric | count, `timestamp ≥ now-24h` |
| Critical/High open | Metric | count, `rule.level ≥ 10`, status open |
| Alerts over time | Area | date_histogram `timestamp` (1h) split by `rule.level` band |
| Top 10 rules | Data table | terms `rule.id` × `rule.description` |
| Agents up/down | Gauge | active vs disconnected (agent status) |
| Top affected hosts | Bar | terms `agent.name`, `rule.level ≥ 7` |
| MITRE tactics (24h) | Pie | terms `rule.mitre.tactic` |

---

## 2. L1 Triage View

**Purpose:** the working queue for L1 — actionable medium/high alerts, newest first.
**Audience:** L1 analysts. **Filter baseline:** `rule.level ≥ 7`.

| Panel | Type | Query / aggregation |
|---|---|---|
| Triage queue | Saved search (table) | `rule.level ≥ 7`, cols: `timestamp, agent.name, rule.level, rule.description, srcip` sort `timestamp desc` |
| New since shift start | Metric | count `rule.level ≥ 7 AND timestamp ≥ now/d` |
| By severity band | Bar | terms on scripted level band (12-15/10-11/7-9) |
| Repeat offenders (srcip) | Data table | terms `data.srcip`, `rule.groups: authentication_failures` |
| Auth failure spikes | Line | date_histogram on rule 5712/5710 |
| Unassigned criticals | Saved search | `rule.level ≥ 12` not yet in a case (join via platform) |

> Pair with the platform's AI-triage: L1 reads the AI verdict/summary alongside the
> raw alert. Disagreements feed the feedback loop.

---

## 3. MITRE ATT&CK View

**Purpose:** coverage and active technique visibility. **Audience:** L2 / hunters.

| Panel | Type | Query / aggregation |
|---|---|---|
| Tactics heatmap | Heat map | `rule.mitre.tactic` × date_histogram |
| Top techniques | Data table | terms `rule.mitre.id` × `rule.mitre.technique` |
| Technique trend | Line | date_histogram split by `rule.mitre.id` (top 10) |
| Tactic distribution | Pie | terms `rule.mitre.tactic` |
| Untriaged ATT&CK hits | Saved search | `rule.mitre.id: *` AND `rule.level ≥ 10` |

> The platform now stores `mitre_tactic`/`mitre_technique` on alerts (poller
> normalizes them). Keep the indexer field `rule.mitre.*` and the platform field
> in sync for cross-referencing.

---

## 4. Endpoint Health Dashboard

**Purpose:** is every endpoint reporting? **Audience:** SOC ops.

| Panel | Type | Query / aggregation |
|---|---|---|
| Agents Active/Disconnected/Never | Metric ×3 | agent status (manager API / `agent.status`) |
| Disconnected agents | Data table | `rule.id: 503` recent, terms `agent.name` |
| Last-seen per agent | Data table | max `timestamp` by `agent.name` (stale > 15 min = red) |
| Reconnect events | Line | rule 502 over time |
| Silent endpoints (no events 1h) | Saved search | agents with no docs in last 1h (alert if critical asset) |
| FIM/syscheck activity | Bar | `rule.groups: syscheck` by `agent.name` |

---

## 5. Enrollment Failure Dashboard

**Purpose:** surface every enrollment problem from [MONITORING-RULES.md §1a](MONITORING-RULES.md).
**Audience:** SOC ops. **Depends on** the custom ops_health rules (100010–100014).

| Panel | Type | Query / aggregation |
|---|---|---|
| Invalid password (24h) | Metric + table | auth rule matches `Invalid password` |
| Duplicate agent name | Table | rule 100011 |
| Key already in use | Table | rule 100012 |
| Invalid ID | Table | rule 100013 |
| Never-connected agents | Saved search | agent status `Never connected` |
| Enrollment errors over time | Line | date_histogram on `group: enrollment` |
| Failures by source host | Bar | terms `data.srcip` / `agent.name` |

---

## 6. Critical Server Dashboard

**Purpose:** focused view of Payless's crown-jewel servers (DB, payment, AD, domain
controllers). **Audience:** L2 / IR. **Scope:** a CDB list / tag of critical hostnames.

| Panel | Type | Query / aggregation |
|---|---|---|
| Alerts on critical assets | Saved search | `agent.name` IN critical-list, `rule.level ≥ 7` |
| Privilege escalation | Table | MITRE T1068/T1548 on critical hosts |
| FIM changes (PCI) | Table | `rule.groups: syscheck` on critical hosts |
| Auth anomalies | Line | failed/success login ratio per critical host |
| New processes / LOLBins | Table | Sysmon/eventchannel on critical hosts |
| Vulnerability findings | Table | platform vuln module, critical assets |

> Maintain the critical-asset list as a CDB list (`/var/ossec/etc/lists/critical_servers`)
> so it's backed up and reusable across rules and dashboards.

---

## 7. Retail Endpoint Dashboard (POS / store)

**Purpose:** retail-specific visibility — POS terminals, store back-office, kiosks.
**Audience:** SOC ops. **Scope:** agents grouped `pos` / `store-*`.

| Panel | Type | Query / aggregation |
|---|---|---|
| POS endpoints up/down | Metric | agent status filtered to `group: pos` |
| Card-data-path FIM | Table | `syscheck` on payment-app directories |
| USB / removable media | Table | rules for device insertion on POS |
| Outbound to rare destinations | Bar | terms `data.dstip` for POS, low-frequency |
| After-hours activity | Line | events on store agents outside trading hours |
| Known-bad IP hits (TI) | Table | CDB/TI list match from store endpoints |

---

## 8. Weekly Coverage Report

**Purpose:** the artifact backing the Monday ops review; complements
`scripts/weekly-capacity-report.sh`. **Audience:** SOC lead. **Delivery:** scheduled
PDF via the platform's report generator + the dashboard for drill-down.

| Section | Source |
|---|---|
| Alert volume by severity (7d) | weekly-capacity-report §2 |
| Top noisy rules + tuning status | weekly-capacity-report §3 + MONITORING-RULES changelog |
| Agent fleet growth & gaps | weekly-capacity-report §1 |
| MITRE technique coverage | Dashboard #3 export |
| Index storage & retention runway | weekly-capacity-report §4–5 |
| Open vs closed cases, MTTR/MTTD | platform `/metrics` |
| Integration health summary | INTEGRATIONS-HEALTH checklist results |

> Schedule via the platform report scheduler (now generating real PDFs). Email to
> the SOC lead + Payless stakeholder distribution.

---

## Authoring & version control

1. Build each dashboard in the Wazuh Dashboard UI.
2. Export the full set:
   ```bash
   curl -sk -u admin:$PASS -XPOST "$DASH/api/saved_objects/_export" \
     -H 'osd-xsrf:true' -H 'Content-Type: application/json' \
     -d '{"type":["index-pattern","visualization","dashboard","search","lens"],"includeReferencesDeep":true}' \
     > docs/operations/dashboards/payless-dashboards.ndjson
   ```
3. Commit the NDJSON. Re-import on any dashboard rebuild.

---

### Related
- Rules feeding these panels: [MONITORING-RULES.md](MONITORING-RULES.md)
- Rebuild/import procedure: [BACKUP-RESTORE.md §5](BACKUP-RESTORE.md)
