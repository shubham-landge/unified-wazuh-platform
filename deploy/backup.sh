#!/bin/bash
# PostgreSQL backup script for SOC platform
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/opt/backups/soc-platform}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/soc_platform_${TIMESTAMP}.sql.gz"

mkdir -p "$BACKUP_DIR"

echo "=== SOC Platform Database Backup ==="
echo "Backup: $BACKUP_FILE"

# Get DB credentials from docker compose
DB_PASSWORD=$(grep DATABASE_PASSWORD docker-compose.yml | head -1 | awk '{print $2}')

# Run pg_dump via docker
sudo docker compose exec -T postgres pg_dump \
    -U soc_user \
    -d soc_platform \
    --clean \
    --if-exists \
    --no-owner \
    --no-acl \
    2>/dev/null | gzip > "$BACKUP_FILE"

# Verify
if [ -f "$BACKUP_FILE" ]; then
    SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
    echo "✅ Backup complete: $SIZE"
else
    echo "❌ Backup failed"
    exit 1
fi

# Clean old backups
find "$BACKUP_DIR" -name "soc_platform_*.sql.gz" -mtime +"$RETENTION_DAYS" -delete
echo "   Old backups cleaned (retention: ${RETENTION_DAYS}d)"

# Restore command reminder:
# gunzip -c soc_platform_TIMESTAMP.sql.gz | docker compose exec -T postgres psql -U soc_user -d soc_platform
