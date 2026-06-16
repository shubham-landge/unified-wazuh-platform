# SOC Operations Runbooks — Payless / Unified Wazuh Platform

Operational runbooks for the on-call SOC engineer. Each runbook is self-contained:
symptoms → diagnosis → step-by-step fix → verification.

> **Manager paths assume `/var/ossec`.** Indexer = Wazuh Indexer (OpenSearch).
> Replace `<MANAGER>`, `<AGENT_ID>`, `<AGENT_NAME>` with real values.

---

## Index

1. [Agent Enrollment Troubleshooting](#1-agent-enrollment-troubleshooting)
2. [Agent Clean Reinstall](#2-agent-clean-reinstall)
3. [Password Rotation](#3-password-rotation)
4. [Emergency Stop Procedure](#4-emergency-stop-procedure)

---

## 1. Agent Enrollment Troubleshooting

**When to use:** A new endpoint won't enroll, or shows "Never connected" / "Disconnected"
on the manager. Drives the *Enrollment Failure* dashboard.

### Diagnose first

```bash
# On the manager — current agent state
/var/ossec/bin/agent_control -l | grep -iE 'never connected|disconnected'

# Watch enrollment daemon live while the agent tries to register
tail -f /var/ossec/logs/ossec.log | grep -iE 'authd|enrollment|agent-auth'
```

### Symptom → cause → fix

| Log message / symptom | Cause | Fix |
|---|---|---|
| `Invalid password` | Agent's `authd.pass` doesn't match manager's | Copy the manager's `/var/ossec/etc/authd.pass` to the agent, or re-run `agent-auth -P <pass>`. See §3 if rotating. |
| `Duplicate agent name` | An agent with `<AGENT_NAME>` already exists | Remove the stale record: `/var/ossec/bin/manage_agents -r <AGENT_ID>`, then re-enroll. Or enroll with a unique name. |
| `Agent key already in use` | `client.keys` entry reused on two hosts (cloned VM/image) | Delete the agent on manager, wipe `client.keys` on the new host, re-enroll so it gets a fresh key. **Never** clone an image with `client.keys` populated. |
| `Invalid ID` | Agent references an ID the manager no longer has | Re-enroll from scratch (clean `client.keys` on agent) so the manager assigns a new ID. |
| Agent stuck `Never connected` | Port 1514/udp-tcp blocked, or wrong manager IP | Confirm reachability: `nc -vz <MANAGER> 1514`. Check agent `ossec.conf` `<server><address>`. |
| `Agent disconnected` (was active) | Network drop, agent service stopped, or keepalive lost | Restart agent service; confirm `1514` open; check endpoint clock skew (>15 min skew breaks enrollment crypto). |
| TLS/cert errors during `agent-auth` | Manager enrollment cert mismatch | Verify `/var/ossec/etc/sslmanager.cert`. Use `-v <CA>` or disable cert verification only in lab. |

### Manual enrollment (gold path)

```bash
# On the agent
/var/ossec/bin/agent-auth -m <MANAGER> -p 1515 -A <AGENT_NAME> -P '<authd.pass>'
systemctl restart wazuh-agent

# On the manager — confirm it appears and connects
/var/ossec/bin/agent_control -l | grep <AGENT_NAME>
```

### Verify resolved

```bash
/var/ossec/bin/agent_control -i <AGENT_ID>   # should show "Active"
```
Then confirm alerts from that agent land in the indexer (Discover →
`agent.name: "<AGENT_NAME>"`, last 15 min).

---

## 2. Agent Clean Reinstall

**When to use:** Agent is corrupted, half-upgraded, key-conflicted, or "Never connected"
won't clear. This fully removes and re-enrolls.

### Step 1 — Remove the agent record on the manager

```bash
/var/ossec/bin/manage_agents -r <AGENT_ID>     # or use -r all guided menu
```

### Step 2 — Purge the agent host

**Linux:**
```bash
systemctl stop wazuh-agent
apt-get remove --purge wazuh-agent -y   # or: yum remove wazuh-agent -y
rm -rf /var/ossec                        # nukes client.keys + state
```

**Windows (PowerShell, admin):**
```powershell
Stop-Service -Name WazuhSvc
msiexec.exe /x wazuh-agent-*.msi /qn
Remove-Item -Recurse -Force "C:\Program Files (x86)\ossec-agent"
```

### Step 3 — Reinstall + enroll

```bash
# Linux (set manager + enrollment at install time)
WAZUH_MANAGER="<MANAGER>" WAZUH_AGENT_NAME="<AGENT_NAME>" \
  WAZUH_REGISTRATION_PASSWORD="<authd.pass>" \
  apt-get install wazuh-agent
systemctl enable --now wazuh-agent
```

### Step 4 — Verify

```bash
/var/ossec/bin/agent_control -i <AGENT_ID>   # Active
```
Confirm new alerts in indexer within 5 minutes. If it re-conflicts on the key,
you skipped Step 1 — the manager still holds the old record.

---

## 3. Password Rotation

Covers **three** distinct secrets. Rotate on a schedule and after any suspected exposure.

### 3a. Enrollment password (`authd.pass`)

```bash
# On the manager — generate and install a new enrollment secret
openssl rand -base64 24 > /var/ossec/etc/authd.pass
chmod 640 /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass
systemctl restart wazuh-manager
```
- **Impact:** Only affects *new* enrollments. Existing agents keep their keys and
  are unaffected.
- **Distribute** the new value to your provisioning system / image build (never commit it).
- Back it up immediately (`scripts/wazuh-config-backup.sh` captures it, encrypted).

### 3b. Wazuh API / indexer admin passwords

```bash
# Wazuh indexer (OpenSearch security) admin password — run the tool shipped with the indexer
cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools
./wazuh-passwords-tool.sh --change-all          # interactive, rotates all internal users
```
Then update every consumer of those credentials:
- Filebeat output (`/etc/filebeat/filebeat.yml` → `output.elasticsearch.password`)
- Wazuh dashboard (`/etc/wazuh-dashboard/opensearch_dashboards.yml`)
- **This platform's** `.env` / secrets store: `WAZUH_INDEXER_PASSWORD`, `WAZUH_API_PASSWORD`

```bash
filebeat test output     # confirm new creds work before restarting services
systemctl restart filebeat wazuh-dashboard
docker compose restart api worker   # platform picks up new env
```

### 3c. Platform secrets (JWT, API keys, DB)

| Secret | Where | Rotation |
|---|---|---|
| `JWT_SECRET_KEY` | platform `.env` / Vault | Rotating invalidates all sessions — users must re-login. Do during low traffic. |
| `API_KEYS` | platform `.env` | Add the new key, distribute, then remove the old one (overlap window). |
| `DATABASE_PASSWORD` | postgres + `.env` | `ALTER USER soc_user WITH PASSWORD '…';` then update `.env`, `docker compose up -d`. |

### Verify (all)

- New enrollments succeed with the new `authd.pass`.
- `filebeat test output` → OK; alerts still flowing.
- Platform `/health` green; login works with rotated JWT secret.

---

## 4. Emergency Stop Procedure

**When to use:** Active incident requires halting ingestion/automation — e.g. a
compromised integration, runaway automated response, log poisoning, or a tenant
data-isolation breach. Goal: **stop the bleeding without destroying evidence.**

### Severity ladder — stop the smallest blast radius first

**Level 1 — Halt automated response only** (stop SOAR taking actions, keep visibility):
```bash
# Disable active-response on the manager (stops automated blocks/kills)
# Comment out <active-response> blocks or set <disabled>yes</disabled>, then:
systemctl restart wazuh-manager
# Pause platform automation workers (keep API/dashboard for analysts)
docker compose stop worker
```

**Level 2 — Quarantine a bad integration / webhook** (e.g. leaked Teams webhook):
```bash
# Pull the secret immediately so it can't be used mid-incident
#   - rotate/revoke the webhook at the provider (Teams/Slack/PagerDuty)
#   - remove it from /var/ossec/integrations + ossec.conf, restart manager
# Platform side: remove the connector secret from .env / settings and:
docker compose restart api worker
```

**Level 3 — Stop ingestion but preserve data** (suspected log poisoning):
```bash
systemctl stop filebeat            # stop shipping to indexer (queues on disk)
docker compose stop worker         # stop platform alert polling/triage
# Indexer + manager keep running; nothing is deleted. Investigate, then resume.
```

**Level 4 — Full platform halt** (data-isolation breach / tenant leak):
```bash
docker compose stop                # api, worker, dashboard, redis — all down
systemctl stop wazuh-manager filebeat
# Indexer left running read-only for forensics; do NOT delete indices.
```

### Do NOT (preserve evidence)

- ❌ Do not `docker compose down -v` (destroys volumes/DB).
- ❌ Do not delete indices, `client.keys`, or logs.
- ❌ Do not rotate the JWT secret yet if you need to inspect active sessions.

### Resume checklist (after containment)

1. Confirm root cause fixed (revoked secret, patched rule, blocked IP).
2. `systemctl start wazuh-manager filebeat` → `filebeat test output` OK.
3. `docker compose up -d` → `/health` green.
4. Confirm alerts flowing again (Discover, last 5 min).
5. Run `scripts/daily-health-check.sh` for a full green pass.
6. Write the incident timeline; back up `ossec.conf` + rules as the new known-good.

---

### Related
- Backups & rebuild: [BACKUP-RESTORE.md](BACKUP-RESTORE.md)
- Rule monitoring & severity routing: [MONITORING-RULES.md](MONITORING-RULES.md)
- Integration verification: [INTEGRATIONS-HEALTH.md](INTEGRATIONS-HEALTH.md)
