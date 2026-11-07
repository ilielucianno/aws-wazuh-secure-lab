#!/bin/bash
# Daily backup of 1cyber Comply data to S3.
# The instance role may write and read backups but has no s3:DeleteObject permission,
# so a compromised server cannot destroy existing backups. Retention is handled by an
# S3 lifecycle rule (30 days, noncurrent versions 7 days) with versioning enabled.
# Installed as /usr/local/bin/comply-backup.sh, symlinked from /etc/cron.daily/comply-backup
set -euo pipefail
BUCKET="comply-backup-lucian-1982"
STAMP=$(date -u +%Y%m%d-%H%M%S)
VOL=/var/lib/docker/volumes/1cyber-comply_comply-data/_data
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"; docker exec 1cyber-comply rm -f /data/comply-backup.db || true' EXIT
# Consistent copy of the live SQLite database (online backup API)
docker exec 1cyber-comply python -c "import sqlite3; s=sqlite3.connect('/data/comply.db'); d=sqlite3.connect('/data/comply-backup.db'); s.backup(d); d.close(); s.close()"
tar -czf "$TMP/comply-$STAMP.tar.gz" -C "$VOL" --exclude=comply.db --exclude=comply.db-wal --exclude=comply.db-shm .
/snap/bin/aws s3 cp "$TMP/comply-$STAMP.tar.gz" "s3://$BUCKET/daily/" --region eu-north-1 --only-show-errors
echo "Backup uploaded: comply-$STAMP.tar.gz"
