#!/bin/bash
# =============================================================================
# Wazuh Configuration Backup — Manager, Filebeat, Certificates
# -----------------------------------------------------------------------------
# Backs up everything required to rebuild a Wazuh manager from scratch:
#   - ossec.conf (manager config)
#   - client.keys (agent enrollment keys)            [SENSITIVE]
#   - local rules / decoders / CDB lists
#   - authd.pass (enrollment password)               [SENSITIVE → encrypted]
#   - integration scripts (custom_*, integrations/)
#   - Filebeat config + ingest pipelines
#   - TLS certificates (manager, indexer, filebeat)  [SENSITIVE → encrypted]
#
# Sensitive artifacts (client.keys, authd.pass, certs, private keys) are placed
# in a SEPARATE archive that is GPG-encrypted if BACKUP_GPG_RECIPIENT is set.
#
#   Cron example (02:30 daily):
#     30 2 * * *  /opt/soc-platform/scripts/wazuh-config-backup.sh >> /var/log/wazuh-backup.log 2>&1
#
# Env vars:
#   BACKUP_DIR            default /opt/backups/wazuh-config
#   RETENTION_DAYS        default 30
#   BACKUP_GPG_RECIPIENT  GPG key id/email for encrypting the secrets archive
#   OFFSITE_S3_BUCKET     optional: s3://bucket/prefix to sync after backup
# =============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/opt/backups/wazuh-config}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
BACKUP_GPG_RECIPIENT="${BACKUP_GPG_RECIPIENT:-}"
OFFSITE_S3_BUCKET="${OFFSITE_S3_BUCKET:-}"
TS=$(date +%Y%m%d_%H%M%S)
OSSEC="/var/ossec"
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$BACKUP_DIR"
echo "=== Wazuh Config Backup — ${TS} ==="

# ---- Non-sensitive config -------------------------------------------------
mkdir -p "$STAGE/config" "$STAGE/secrets"

copy() { [ -e "$1" ] && cp -a "$1" "$2" && echo "   + $1" || echo "   - skip (missing): $1"; }

echo "[1/3] Manager + rules + integrations"
copy "$OSSEC/etc/ossec.conf"               "$STAGE/config/"
copy "$OSSEC/etc/rules/local_rules.xml"    "$STAGE/config/"
copy "$OSSEC/etc/decoders/local_decoder.xml" "$STAGE/config/"
# Whole custom rules/decoders/lists trees (catch all local additions)
[ -d "$OSSEC/etc/rules" ]    && cp -a "$OSSEC/etc/rules"    "$STAGE/config/rules"    && echo "   + etc/rules/"
[ -d "$OSSEC/etc/decoders" ] && cp -a "$OSSEC/etc/decoders" "$STAGE/config/decoders" && echo "   + etc/decoders/"
[ -d "$OSSEC/etc/lists" ]    && cp -a "$OSSEC/etc/lists"    "$STAGE/config/lists"    && echo "   + etc/lists/ (CDB lists)"
# Integration scripts (Slack/Teams/VirusTotal/custom)
[ -d "$OSSEC/integrations" ] && cp -a "$OSSEC/integrations" "$STAGE/config/integrations" && echo "   + integrations/"

echo "[2/3] Filebeat config + pipelines"
copy "/etc/filebeat/filebeat.yml"          "$STAGE/config/"
[ -d "/etc/filebeat/modules.d" ] && cp -a "/etc/filebeat/modules.d" "$STAGE/config/filebeat-modules.d" && echo "   + filebeat modules.d/"
[ -d "/usr/share/filebeat/module/wazuh" ] && echo "   (wazuh filebeat module present — package-managed, not copied)"

# ---- Sensitive artifacts (separate, encrypted) ----------------------------
echo "[3/3] Secrets: client.keys, authd.pass, certificates"
copy "$OSSEC/etc/client.keys"              "$STAGE/secrets/"
copy "$OSSEC/etc/authd.pass"               "$STAGE/secrets/"
# Certificates (manager + indexer + filebeat)
for certdir in "$OSSEC/etc/sslmanager.cert" "$OSSEC/etc/sslmanager.key" \
               /etc/filebeat/certs /etc/wazuh-indexer/certs; do
    copy "$certdir" "$STAGE/secrets/"
done

# ---- Package archives -----------------------------------------------------
CONFIG_TAR="$BACKUP_DIR/wazuh-config_${TS}.tar.gz"
SECRETS_TAR="$BACKUP_DIR/wazuh-secrets_${TS}.tar.gz"

tar -czf "$CONFIG_TAR" -C "$STAGE" config
echo "✅ Config archive: $CONFIG_TAR ($(du -h "$CONFIG_TAR" | cut -f1))"

tar -czf "$STAGE/secrets.tar.gz" -C "$STAGE" secrets
if [ -n "$BACKUP_GPG_RECIPIENT" ]; then
    gpg --batch --yes --trust-model always -r "$BACKUP_GPG_RECIPIENT" \
        -o "${SECRETS_TAR}.gpg" -e "$STAGE/secrets.tar.gz"
    chmod 600 "${SECRETS_TAR}.gpg"
    echo "🔐 Secrets archive (encrypted): ${SECRETS_TAR}.gpg"
else
    cp "$STAGE/secrets.tar.gz" "$SECRETS_TAR"
    chmod 600 "$SECRETS_TAR"
    echo "⚠️  Secrets archive UNENCRYPTED: $SECRETS_TAR"
    echo "    Set BACKUP_GPG_RECIPIENT to encrypt client.keys / authd.pass / certs at rest."
fi

# ---- Offsite sync ---------------------------------------------------------
if [ -n "$OFFSITE_S3_BUCKET" ] && command -v aws >/dev/null 2>&1; then
    aws s3 cp "$CONFIG_TAR" "$OFFSITE_S3_BUCKET/" --only-show-errors
    [ -f "${SECRETS_TAR}.gpg" ] && aws s3 cp "${SECRETS_TAR}.gpg" "$OFFSITE_S3_BUCKET/" --only-show-errors
    echo "☁️  Synced to ${OFFSITE_S3_BUCKET}"
fi

# ---- Retention ------------------------------------------------------------
find "$BACKUP_DIR" -name 'wazuh-config_*.tar.gz'  -mtime +"$RETENTION_DAYS" -delete
find "$BACKUP_DIR" -name 'wazuh-secrets_*'         -mtime +"$RETENTION_DAYS" -delete
echo "   Retention applied (${RETENTION_DAYS}d). Done."
