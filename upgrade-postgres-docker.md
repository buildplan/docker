# PostgreSQL Major Version Upgrade Guide for Docker

This generic guide covers upgrading PostgreSQL containers from one major version to another (e.g., 16→17, 17→18).

## Prerequisites

**Compatibility check**: Verify your application supports the target PostgreSQL version.

**Maintenance window**: Plan for 5-30 minutes of downtime depending on database size.

**Disk space**: Ensure sufficient space for backup files and duplicate data directories.

**Environment variables**: Know your `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB` values.

## Upgrade Process

### 1. Create Full Backup

```bash
# Stop dependent services (not the database)
docker compose stop <app-service-name>

# Create SQL dump using pg_dumpall
docker compose exec <db-service-name> pg_dumpall -U <username> > ./backup.sql

# Verify backup file exists and has content
ls -lh ./backup.sql
head -n 20 ./backup.sql
```

The backup should show PostgreSQL dump headers and be larger than a few kilobytes.

### 2. Stop and Backup Data Directory

```bash
# Stop database container
docker compose stop <db-service-name>

# Backup existing data directory
mv ./<data-dir> ./<data-dir>-backup
mkdir ./<data-dir>
```

Replace `<data-dir>` with your actual data directory path from your volume mount.

### 3. Update PostgreSQL Version

**Option A: Update environment file**

```bash
nano .env
# Change: DB_VER=18-alpine (or 18 for standard)
```

**Option B: Update docker-compose.yml**

```yaml
image: postgres:18-alpine  # or postgres:18
```

Pull the new image:

```bash
docker compose pull <db-service-name>
```


### 4. Start New Database Container

```bash
docker compose up -d <db-service-name>

# Wait 15-20 seconds for initialization
sleep 20

# Check logs for successful startup
docker compose logs <db-service-name>
```

Look for "database system is ready to accept connections".

### 5. Restore Backup

```bash
cat backup.sql | docker exec -i <container-name> psql -U <username> -d postgres
```

**Expected output**: You may see "role already exists" or "database already exists" errors—these are harmless.

### 6. Verify Database

```bash
# Check PostgreSQL version
docker compose exec <db-service-name> psql -U <username> -d postgres -c "SELECT version();"

# List databases
docker compose exec <db-service-name> psql -U <username> -d postgres -c "\l"

# Check table count (replace <database-name>)
docker compose exec <db-service-name> psql -U <username> -d <database-name> -c "\dt"
```


### 7. Start Application Services

```bash
docker compose up -d

# Monitor application logs
docker compose logs -f <app-service-name>
```


### 8. Test Application

Log into your application and verify critical functionality works correctly.

## Best Practices

**Test first**: If possible, test the upgrade on a staging environment or copy of your data before production.

**Read release notes**: Review PostgreSQL release notes for your target version to identify breaking changes.

**Keep backups**: Maintain both SQL dump and old data directory for at least one week after successful upgrade.

**Use same variant**: If upgrading from standard PostgreSQL, use standard; if from Alpine, use Alpine.

**Update extensions**: After upgrade, update any PostgreSQL extensions with `ALTER EXTENSION <name> UPDATE;`.

**Refresh statistics**: Run `ANALYZE;` on your databases after restore to update query planner statistics.

**Monitor performance**: Watch application performance for several days after upgrade.

## Troubleshooting

### "role already exists" or "database already exists"

**Cause**: PostgreSQL auto-created these from environment variables during initialization.

**Solution**: Ignore these errors—the restore continues successfully and populates existing objects with your data.

### Connection refused after restore

**Cause**: Using wrong database name in connection string.

**Solution**: Verify database name matches your `POSTGRES_DB` environment variable using `\l` command.

### Permission denied on data directory

**Cause**: PostgreSQL runs as UID 70 inside containers.

**Solution**: This is normal—use `docker compose exec` commands to access database, or `sudo` for host filesystem inspection.

### Alpine compatibility issues

**Symptoms**: DNS resolution failures, connection problems, locale errors.

**Solution**: Switch to standard Debian-based PostgreSQL image (`postgres:18` instead of `postgres:18-alpine`).

### Restore hangs or is very slow

**Cause**: Large database taking time to restore.

**Solution**: Be patient—restoration time scales with database size. Monitor with `docker compose logs -f <db-service-name>`.

## Rollback Procedure

If issues occur after upgrade:

```bash
# Stop all services
docker compose down

# Restore old data directory
rm -rf ./<data-dir>
mv ./<data-dir>-backup ./<data-dir>

# Revert version in .env or docker-compose.yml
nano .env  # Change back to old version

# Restart services
docker compose up -d
```


## Version-Specific Notes

**Minor version updates** (e.g., 18.0→18.1): Simply update the image tag and restart—no backup/restore needed.

**Major version upgrades** (e.g., 16→17→18): You can skip intermediate versions using this dump/restore method.

**Alpine vs Standard**: Alpine images are ~120MB smaller but may have compatibility issues with some applications.

<div align="center">⁂</div>
