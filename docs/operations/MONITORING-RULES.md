# Monitoring Rules, Severity Routing & Tuning — Payless SOC

The detections the SOC must actively watch, how alerts are routed by severity,
and how to tame noisy rules. Rule IDs below are Wazuh's built-in IDs unless
marked **(custom)** — add custom ones to `/var/ossec/etc/rules/local_rules.xml`.

---

## 1. Critical Rules to Monitor (operational health + security)

These fall into two buckets: **platform/agent health** (is the pipeline working?)
and **security signal** (is something bad happening?). Both must be on a dashboard
and wired to severity routing.

### 1a. Wazuh / agent operational health

| Condition | Rule ID(s) | Level | Why it matters | Route |
|---|---|---|---|---|
| **Invalid password** (enrollment) | 2501, 5710-series auth | 5–8 | Failed agent enrollment or SSH auth failures | Enrollment-failure dashboard + L1 |
| **Duplicate agent name** | 4002 / authd log pattern **(custom)** | 8 | Image cloning / misprovisioning | Enrollment-failure dashboard |
| **Agent key already in use** | authd `agent key already in use` **(custom)** | 8 | Cloned `client.keys`, key conflict | Enrollment-failure dashboard |
| **Invalid ID** | authd `Invalid ID` **(custom)** | 7 | Agent/manager state drift | Enrollment-failure dashboard |
| **Agent disconnected** | 503 (agent stopped) / 505 | 3–7 | Endpoint lost visibility | Endpoint-health dashboard + L1 if critical asset |
| **Agent never connected** | derived from `agent_control` / 502 | 5 | New endpoint never reported | Enrollment-failure dashboard |
| **Agent started/connected** | 502 | 3 | Recovery signal (correlate with disconnect) | Endpoint-health dashboard |
| **Event queue flooded** | 1234 (analysisd queue full) **(custom)** | 12 | Events being **dropped** — blind spot forming | Page on-call immediately |
| **Manager / indexer errors** | 1002 (generic error), 1003, ossec.log errors | 5–12 | Core pipeline failing | Page on-call |
| **Filebeat errors** | filebeat module / 1002 on filebeat logs **(custom)** | 7–10 | Alerts not reaching indexer | Page on-call |

> **Custom rules required.** Wazuh doesn't ship dedicated IDs for "duplicate
> agent name", "key already in use", "invalid ID", or "event queue flooded" as
> first-class alerts — they appear in `ossec.log`/authd logs. Add a localfile +
> custom rules so they become alertable (template in §4).

### 1b. Security signal (retail-relevant)

| Condition | Rule group / ID | Level | Route |
|---|---|---|---|
| Brute force / auth failure burst | `authentication_failures`, 5712 | 10 | L1 triage + MITRE (T1110) |
| Successful login after brute force | 5715 + correlation | 12 | Page on-call |
| Malware / IOC match | `virustotal`, integration rules | 12 | Page on-call |
| New CDB-listed bad IP/hash hit | custom CDB list match | 10–12 | L1 + TI enrich |
| PCI-relevant file change (FIM) | `syscheck`, 550/553/554 | 7–10 | Critical-server dashboard |
| Privilege escalation | MITRE T1068/T1548 mapped rules | 10–12 | MITRE view + page |
| Suspicious PowerShell / LOLBins | Sysmon/eventchannel rules | 10 | MITRE view |

---

## 2. Severity Routing

Map Wazuh `rule.level` → SOC action. Wire this in **both** places: the platform's
notification connectors (Slack/Teams/PagerDuty/email) and the dashboard filters.

| Rule level | Severity | Routing | SLA (ack) |
|---|---|---|---|
| **12–15** | Critical | PagerDuty page on-call + Teams `#soc-critical` + auto-create case | 15 min |
| **10–11** | High | Teams `#soc-alerts` + L1 triage queue + AI triage | 1 hour |
| **7–9** | Medium | L1 triage queue (dashboard), AI triage, no page | 4 hours |
| **4–6** | Low | Dashboard only, aggregated; weekly review | best-effort |
| **0–3** | Info | Indexed, not alerted; available for hunting | — |

### Where to configure

**Platform side** (this repo) — severity → connector mapping lives in the
notification routing config. Confirm each tier maps to the right connector and
that webhook secrets are in the secret store, not the DB (see
[INTEGRATIONS-HEALTH.md](INTEGRATIONS-HEALTH.md)).

**Wazuh manager side** — use `<email_alerts>` / integration `level` thresholds in
`ossec.conf`:
```xml
<integration>
  <name>custom-teams</name>
  <level>12</level>            <!-- only page on level >= 12 -->
  <hook_url>SECRET_FROM_ENV</hook_url>
  <alert_format>json</alert_format>
</integration>
```

---

## 3. Noisy Rule Tuning

Noisy rules drown real signal and burn AI-triage budget. Find them with the
**weekly capacity report** (`scripts/weekly-capacity-report.sh §3`) or:

```bash
# Top 20 firing rules in the last 24h
curl -sk -u admin:$PASS "$INDEXER/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{
  "size":0,"query":{"range":{"timestamp":{"gte":"now-24h"}}},
  "aggs":{"r":{"terms":{"field":"rule.id","size":20}}}}'
```

### Tuning decision tree

For each noisy rule, in order of preference:

1. **False positive on a known-good pattern?** → write a *more specific* override
   rule that drops/relabels it, keyed on the field that distinguishes benign:
   ```xml
   <!-- local_rules.xml: silence benign vendor agent updates matching rule 2902 -->
   <rule id="100200" level="0">
     <if_sid>2902</if_sid>
     <match>PaylessVendorUpdater</match>
     <description>Benign: Payless vendor updater (tuned out)</description>
   </rule>
   ```
2. **Legit but low value, high volume?** → lower its level so it stops paging
   (drops it into the Low/Info band of §2) rather than suppressing entirely.
3. **Per-agent noise** (one chatty host)? → scope the override with `<agent_name>`
   or a CDB list of exception hosts, not a global mute.
4. **Truly useless in this environment?** → set `level 0` (Wazuh discards level 0).
   Document *why* in the rule comment and in this file's changelog.

### Tuning guardrails

- ❌ Never disable a rule **group** to kill one noisy rule — you lose sibling detections.
- ❌ Never tune by deleting from the indexer — fix at the rule layer so it stays fixed.
- ✅ Every tuning change is a tracked edit to `local_rules.xml`, backed up by
  `wazuh-config-backup.sh`, and noted below.
- ✅ Re-run the weekly report after tuning to confirm the rule dropped out of the top 20.

### Tuning changelog (append here)

| Date | Rule | Change | Reason | By |
|---|---|---|---|---|
| _example_ 2026-06-17 | 2902 → +100200 | level 0 override on `PaylessVendorUpdater` | benign update chatter, 40k/day | analyst |

---

## 4. Custom Rule Templates for Operational Alerts

Add these so the operational-health conditions in §1a become first-class alerts.
Requires a `localfile` reading `ossec.log` (analysisd/authd write here).

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->

<group name="wazuh,ops_health,">

  <!-- Event queue flooded — events being dropped -->
  <rule id="100010" level="12">
    <decoded_as>ossec</decoded_as>
    <match>Internal queue is full</match>
    <description>Wazuh: analysisd event queue FULL — events are being dropped</description>
    <group>pci_dss_10.6.1,availability,</group>
  </rule>

  <!-- Duplicate agent name during enrollment -->
  <rule id="100011" level="8">
    <match>Duplicate agent name</match>
    <description>Wazuh authd: duplicate agent name on enrollment</description>
    <group>enrollment,</group>
  </rule>

  <!-- Agent key already in use (cloned client.keys) -->
  <rule id="100012" level="8">
    <match>Agent key already in use</match>
    <description>Wazuh authd: agent key already in use (possible cloned host)</description>
    <group>enrollment,</group>
  </rule>

  <!-- Invalid ID -->
  <rule id="100013" level="7">
    <match>Invalid ID</match>
    <description>Wazuh authd: invalid agent ID on enrollment</description>
    <group>enrollment,</group>
  </rule>

  <!-- Filebeat / indexer shipping error surfaced in logs -->
  <rule id="100014" level="10">
    <match>connection error|failed to publish events|indexer error</match>
    <description>Wazuh: log shipping / indexer error — alerts may not be searchable</description>
    <group>availability,</group>
  </rule>

</group>
```

> Wire `localfile` for `ossec.log` if not already present, then
> `systemctl restart wazuh-manager` and confirm the new rule IDs fire by tailing
> a test event. Back up after adding.

---

### Related
- Dashboards that visualize these rules: [DASHBOARDS.md](DASHBOARDS.md)
- Routing connectors & secrets: [INTEGRATIONS-HEALTH.md](INTEGRATIONS-HEALTH.md)
