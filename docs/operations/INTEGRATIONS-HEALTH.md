# Integration Health & Verification — Payless SOC

How to confirm each data source and outbound integration is alive, and how to
keep their secrets safe. Run the cloud checks at onboarding, after any credential
rotation, and on a monthly cadence.

> **Secrets rule:** every webhook URL, client secret, API token, and routing key
> below belongs in the secret store (Vault) or an environment variable — **never**
> in the database, a saved dashboard object, `ossec.conf` in cleartext that's
> committed, or a chat message. See [§7 Secure secret handling](#7-secure-secret-handling).

---

## 1. Indexer Cluster Health

```bash
curl -sk -u admin:$PASS "$INDEXER/_cluster/health?pretty"
```
| Field | Healthy | Action if not |
|---|---|---|
| `status` | `green` (single-node: `yellow` OK) | `red` → unassigned primaries; check disk watermark, `_cat/shards?h=index,shard,state,unassigned.reason` |
| `number_of_nodes` | = expected | a node dropped → check node logs, network |
| `active_shards_percent_as_number` | 100 | <100 → recovery in progress, watch `_recovery` |
| disk | < 85% | ≥ 85% warm, 90% high, 95% **blocks writes** → expand or purge per retention |

Covered automatically by `scripts/daily-health-check.sh §3`.

---

## 2. Filebeat Pipeline

```bash
filebeat test config        # config valid
filebeat test output        # can reach indexer + auth OK
# Confirm today's index is growing:
curl -sk -u admin:$PASS "$INDEXER/wazuh-alerts-*-$(date +%Y.%m.%d)/_count"
```
| Symptom | Cause | Fix |
|---|---|---|
| `test output` fails auth | rotated indexer password not propagated | update `output.elasticsearch.password`, restart filebeat |
| Config OK, output OK, no new docs | manager not producing alerts, or pipeline missing | `filebeat setup --pipelines`; check `wazuh-manager` analysisd |
| Backpressure / queue growing | indexer slow or disk watermark | resolve indexer disk; filebeat will drain its spool |

---

## 3. Syslog / Firewall / Network Integrations

For appliances shipping syslog into Wazuh (firewalls, switches, WAF, proxies).

| Check | How |
|---|---|
| Manager listening for syslog | `ss -lunp | grep 514` (UDP) / `ss -ltnp | grep 514` (TCP) on the manager |
| `<remote>` config present | `ossec.conf` has `<remote><connection>syslog</connection>` with allowed-IPs |
| Events arriving per source | Discover: `location: "*firewall*"` or by `data.srcip` of the appliance; last 15 min |
| Decoder coverage | confirm the vendor decoder matches (no `data.full_log` left raw) — add custom decoder if needed |
| Per-source heartbeat | build a "silent source" alert: no events from appliance IP in 1h → ops_health |

> Map each network source to an expected EPS baseline so a silent firewall is
> caught by the Endpoint/Coverage dashboards, not discovered during an incident.

---

## 4. Microsoft / Cloud Integrations

### 4a. Microsoft Graph (M365 security/audit)

| Check | How / expected |
|---|---|
| App registration exists | Azure AD → App registrations → the SOC app is present, not expired |
| **App permissions granted** | Graph API perms (e.g. `SecurityEvents.Read.All`, `AuditLog.Read.All`) show **"Granted for <tenant>"** (admin consent ✓) |
| Client secret valid | secret not expired (Azure shows expiry); rotate before expiry, store in Vault |
| **Token retrieval works** | `curl -s -X POST "https://login.microsoftonline.com/<TENANT>/oauth2/v2.0/token" -d "client_id=<ID>&scope=https://graph.microsoft.com/.default&client_secret=<SECRET>&grant_type=client_credentials"` → returns `access_token` |
| **Logs arriving** | Discover: events with `location`/`integration: azure` or `office365` in last hour; confirm sign-ins/audit present |

### 4b. Office 365 / Azure activity logs

| Check | Expected |
|---|---|
| Wazuh `office365` / `azure-logs` module enabled | `ossec.conf` `<wodle name="office365">` / `azure-logs` configured |
| Subscription/content types active | Exchange, SharePoint, AzureAD, DLP subscriptions enabled in the tenant |
| Ingest confirmed | O365 audit events visible in indexer; count > 0 in last hour |
| Clock/scope | service account has the right Management Activity API scopes |

### 4c. AWS CloudTrail (if in scope)

| Check | Expected |
|---|---|
| Wodle configured | `ossec.conf` `<wodle name="aws-s3">` with the CloudTrail bucket |
| Bucket access | IAM role/keys can `s3:GetObject` + `s3:ListBucket` on the trail bucket |
| SQS (if used) | queue receiving notifications; not backing up |
| Ingest confirmed | CloudTrail events in indexer last hour; `aws.source: cloudtrail` |
| Regions | all in-scope regions' trails are covered |

---

## 5. Teams / Webhook Outbound

| Check | How |
|---|---|
| Webhook still valid | send a test card: `curl -s -X POST -H 'Content-Type: application/json' -d '{"text":"SOC integration test"}' "$TEAMS_WEBHOOK"` → 200 |
| Routing by severity | confirm level-12 test alert reaches `#soc-critical`, level-10 reaches `#soc-alerts` (per [MONITORING-RULES §2](MONITORING-RULES.md)) |
| Secret location | webhook URL in Vault/env, referenced by the connector — **not** in DB or committed config |
| Rotation | rotate webhook if exposed; update secret store; re-test |

If a webhook is suspected compromised, follow [RUNBOOKS §4 Level 2](RUNBOOKS.md#4-emergency-stop-procedure).

---

## 6. Integration Health — verification matrix

Run through this at onboarding and monthly. Record results in the weekly coverage report.

| Integration | Alive check | Secret in Vault? | Last verified |
|---|---|---|---|
| Wazuh indexer | `_cluster/health` green/yellow | n/a (internal) | |
| Filebeat | `filebeat test output` OK | yes (indexer pw) | |
| Syslog/firewall sources | events per source < heartbeat window | n/a | |
| Microsoft Graph | token retrieval + logs arriving | yes (client secret) | |
| O365/Azure logs | events in last hour | yes | |
| AWS CloudTrail | events in last hour | yes (IAM) | |
| Teams/webhook | test card 200 + routing correct | yes (webhook URL) | |
| VirusTotal / TI feeds | API key valid, enrich returns | yes (API key) | |

---

## 7. Secure Secret Handling

**Move every integration secret into secure handling.** Concrete actions for this platform:

1. **Inventory** all secrets in use: indexer/API passwords, Graph client secret,
   AWS keys, Teams/Slack/PagerDuty webhooks, VirusTotal/OTX/MISP keys, JWT secret,
   DB password, `authd.pass`.
2. **Migrate to Vault** (planned in the improvement plan) — until then, keep them
   in `.env`/Docker secrets with `chmod 600`, never in the DB or saved objects.
3. **Audit for leaks:** grep the repo and DB for raw webhook URLs / tokens; if any
   integration secret was ever committed or stored in the DB settings table, rotate
   it and move it to the secret store.
4. **Rotate on a schedule** (see [RUNBOOKS §3](RUNBOOKS.md#3-password-rotation)) and
   immediately on suspected exposure.
5. **Least privilege:** Graph/AWS/O365 service principals get only the read scopes
   they need (`SecurityEvents.Read.All`, `AuditLog.Read.All`, `s3:GetObject` on the
   trail bucket) — nothing broader.

---

### Related
- Stop a compromised integration: [RUNBOOKS.md §4](RUNBOOKS.md)
- Severity routing for outbound: [MONITORING-RULES.md §2](MONITORING-RULES.md)
