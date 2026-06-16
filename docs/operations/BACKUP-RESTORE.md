# Backup, Restore & Rebuild — Payless / Unified Wazuh Platform

What to back up, how, and how to rebuild each tier from those backups.
Automated by [`scripts/wazuh-config-backup.sh`](../../scripts/wazuh-config-backup.sh)
(Wazuh config) and [`deploy/backup.sh`](../../deploy/backup.sh) (platform PostgreSQL).

---

## 1. Backup Coverage Matrix

| Artifact | Path | Sensitive | Covered by | Frequency |
|---|---|---|---|---|
| Manager config | `/var/ossec/etc/ossec.conf` | no | `wazuh-config-backup.sh` | daily |
| Agent keys | `/var/ossec/etc/client.keys` | **yes** 🔐 | `wazuh-config-backup.sh` (encrypted) | daily |
| Local rules | `/var/ossec/etc/rules/local_rules.xml` + `rules/` | no | `wazuh-config-backup.sh` | daily |
| Local decoders | `/var/ossec/etc/decoders/local_decoder.xml` + `decoders/` | no | `wazuh-config-backup.sh` | daily |
| CDB lists | `/var/ossec/etc/lists/` | no | `wazuh-config-backup.sh` | daily |
| Enrollment password | `/var/ossec/etc/authd.pass` | **yes** 🔐 | `wazuh-config-backup.sh` (encrypted) | daily / on rotation |
| Integration scripts | `/var/ossec/integrations/` | partial | `wazuh-config-backup.sh` | daily |
| Filebeat config | `/etc/filebeat/filebeat.yml` + `modules.d/` | partial | `wazuh-config-backup.sh` | daily |
| TLS certificates | manager/indexer/filebeat `certs/` | **yes** 🔐 | `wazuh-config-backup.sh` (encrypted) | daily |
| Indexer data | OpenSearch indices | no | **Snapshot policy** (below) | hourly/daily |
| Platform DB | PostgreSQL `soc_platform` | **yes** | `deploy/backup.sh` (pg_dump) | daily |
| Platform secrets | `.env` / Vault | **yes** 🔐 | Vault backup / sealed `.env` offsite | on change |

> 🔐 Sensitive artifacts go in the **encrypted** secrets archive. Set
> `BACKUP_GPG_RECIPIENT` so `client.keys`, `authd.pass`, and private keys are
> never stored in cleartext at rest. Store the GPG private key separately from
> the backups (different system / offline).

### Run the backups

```bash
# Wazuh config + secrets (run ON the manager host)
BACKUP_GPG_RECIPIENT="soc-backup@payless.example" \
OFFSITE_S3_BUCKET="s3://payless-soc-backups/wazuh-config" \
  /opt/soc-platform/scripts/wazuh-config-backup.sh

# Platform database
BACKUP_DIR=/opt/backups/soc-platform RETENTION_DAYS=30 \
  /opt/soc-platform/deploy/backup.sh
```

### 3-2-1 rule

Keep **3** copies, on **2** media, **1** offsite. The scripts support offsite via
`OFFSITE_S3_BUCKET`. Test a restore monthly — an untested backup is a hope, not a backup.

---

## 2. Indexer Snapshot & Retention Strategy

Wazuh indexer (OpenSearch) data is too large for file copies — use **snapshots**
to a registered repository (S3, or a shared filesystem).

### 2a. Register a snapshot repository (once)

```bash
# S3 repository (requires repository-s3 plugin + IAM creds on indexer nodes)
curl -sk -u admin:$PASS -XPUT "$INDEXER/_snapshot/payless_s3" \
  -H 'Content-Type: application/json' -d '{
    "type":"s3",
    "settings":{"bucket":"payless-soc-snapshots","base_path":"wazuh","region":"us-east-1"}}'

# OR shared filesystem repo (path.repo must be set in opensearch.yml on all nodes)
curl -sk -u admin:$PASS -XPUT "$INDEXER/_snapshot/payless_fs" \
  -H 'Content-Type: application/json' -d '{
    "type":"fs","settings":{"location":"/mnt/snapshots"}}'
```

### 2b. Automated snapshot policy (SLM / ISM)

```bash
# Snapshot Management policy: daily snapshot, keep 14 days / min 7
curl -sk -u admin:$PASS -XPOST "$INDEXER/_plugins/_sm/policies/payless-daily" \
  -H 'Content-Type: application/json' -d '{
    "description":"Daily wazuh-alerts snapshot",
    "creation":{"schedule":{"cron":{"expression":"0 3 * * *","timezone":"UTC"}},
      "time_limit":"1h"},
    "deletion":{"schedule":{"cron":{"expression":"0 5 * * *","timezone":"UTC"}},
      "condition":{"max_age":"14d","max_count":50,"min_count":7}},
    "snapshot_config":{"repository":"payless_s3","indices":"wazuh-*","ignore_unavailable":true}}'
```

### 2c. Retention / lifecycle (ISM rollover)

Recommended index lifecycle for `wazuh-alerts-*` (tune to disk + compliance):

| Phase | Age | Action |
|---|---|---|
| Hot | 0–7d | active writes, fast disk |
| Warm | 7–30d | reduce replicas, force-merge |
| Cold/Searchable snapshot | 30–90d | move to cheaper storage / searchable snapshot |
| Delete | >90d (Payless retention) | drop index (must be snapshotted first) |

> **Decide the retention number with compliance.** Retail/PCI-DSS commonly
> requires ≥1 year of audit logs available (≥3 months hot-searchable). Set
> "Delete" to match Payless's contractual/regulatory requirement, and make sure
> snapshots cover the full retention window even after the hot index is deleted.

### 2d. Verify snapshots

```bash
curl -sk -u admin:$PASS "$INDEXER/_snapshot/payless_s3/_all?pretty" | grep -E 'snapshot|state'
# Each should show "state":"SUCCESS"
```

---

## 3. Restore Procedures

### 3a. Restore indexer data from snapshot

```bash
# Close or delete the target index first if it exists, then restore
curl -sk -u admin:$PASS -XPOST "$INDEXER/_snapshot/payless_s3/<SNAPSHOT_NAME>/_restore" \
  -H 'Content-Type: application/json' -d '{
    "indices":"wazuh-alerts-4.x-2026.06.*",
    "ignore_unavailable":true,
    "include_global_state":false}'
# Track progress
curl -sk -u admin:$PASS "$INDEXER/_recovery?active_only=true&pretty"
```

### 3b. Restore platform database

```bash
gunzip -c /opt/backups/soc-platform/soc_platform_<TS>.sql.gz \
  | docker compose exec -T postgres psql -U soc_user -d soc_platform
docker compose restart api worker
curl -s localhost:8000/health    # confirm green
```

### 3c. Restore Wazuh config / secrets

```bash
# Decrypt secrets archive
gpg -o wazuh-secrets.tar.gz -d wazuh-secrets_<TS>.tar.gz.gpg
tar -xzf wazuh-secrets_<TS>.tar.gz -C /restore
tar -xzf wazuh-config_<TS>.tar.gz  -C /restore

# Place back (manager stopped)
systemctl stop wazuh-manager
cp /restore/config/ossec.conf            /var/ossec/etc/
cp -a /restore/config/rules/*            /var/ossec/etc/rules/
cp -a /restore/config/decoders/*         /var/ossec/etc/decoders/
cp -a /restore/config/lists/*            /var/ossec/etc/lists/
cp /restore/secrets/client.keys          /var/ossec/etc/   # only on the SAME manager identity
cp /restore/secrets/authd.pass           /var/ossec/etc/
chown -R root:wazuh /var/ossec/etc && chmod 640 /var/ossec/etc/client.keys /var/ossec/etc/authd.pass
systemctl start wazuh-manager
```

> ⚠️ Only restore `client.keys` onto a manager that shares the original
> manager's identity. Restoring keys onto a *new* manager identity causes mass
> agent key mismatches — re-enroll agents instead in that case.

---

## 4. Manager Rebuild Procedure

Full rebuild of a lost/corrupted manager.

1. **Provision** a clean host (same OS major version, same Wazuh version as backup).
2. **Install** Wazuh manager (matching version — never restore config across major versions blindly).
   ```bash
   curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
   bash wazuh-install.sh --wazuh-server <node-name>
   ```
3. **Stop** manager, restore config + secrets per §3c.
4. **Reconcile certificates:** if rebuilding with the same hostname/IP, restore
   the manager certs; otherwise regenerate and redistribute indexer/filebeat certs.
5. **Filebeat:** restore `filebeat.yml`, run `filebeat test output`, then
   `filebeat setup --pipelines`.
6. **Start** manager; confirm agents reconnect (they will if `client.keys` +
   identity match). Otherwise re-enroll the fleet (§RUNBOOKS 2).
7. **Verify:** `agent_control -l` shows agents Active; alerts flow to indexer;
   `scripts/daily-health-check.sh` green.

---

## 5. Dashboard Rebuild Procedure

The Wazuh dashboard (OpenSearch Dashboards) holds saved objects: index patterns,
visualizations, dashboards. Back these up via **saved-object export**, not file copy.

### Back up saved objects (do this whenever dashboards change)

```bash
# Export all saved objects (index patterns, visualizations, dashboards)
curl -sk -u admin:$PASS -XPOST "$DASH/api/saved_objects/_export" \
  -H 'osd-xsrf:true' -H 'Content-Type: application/json' \
  -d '{"type":["index-pattern","visualization","dashboard","search","lens"],
       "includeReferencesDeep":true}' > payless-dashboards.ndjson
```
Commit `payless-dashboards.ndjson` to this repo under `docs/operations/dashboards/`
so the Payless dashboard set is version-controlled (see [DASHBOARDS.md](DASHBOARDS.md)).

### Rebuild

1. Reinstall the dashboard package (matching version).
2. Restore `/etc/wazuh-dashboard/opensearch_dashboards.yml` (indexer URL + creds).
3. Import saved objects:
   ```bash
   curl -sk -u admin:$PASS -XPOST "$DASH/api/saved_objects/_import?overwrite=true" \
     -H 'osd-xsrf:true' -F file=@payless-dashboards.ndjson
   ```
4. Verify each dashboard from [DASHBOARDS.md](DASHBOARDS.md) renders with data.

---

### Related
- Operational runbooks: [RUNBOOKS.md](RUNBOOKS.md)
- Dashboard catalog: [DASHBOARDS.md](DASHBOARDS.md)
