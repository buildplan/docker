# PostgreSQL Major Version Upgrade Guide for Docker

This generic guide covers upgrading PostgreSQL containers from one major version to another (e.g., 16→17, 17→18).[1][2][3]

## Prerequisites

**Compatibility check**: Verify your application supports the target PostgreSQL version.[4][5]

**Maintenance window**: Plan for 5-30 minutes of downtime depending on database size.[6][7]

**Disk space**: Ensure sufficient space for backup files and duplicate data directories.[2][4]

**Environment variables**: Know your `POSTGRES_USER`, `POSTGRES_PASSWORD`, and `POSTGRES_DB` values.[8][9]

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

The backup should show PostgreSQL dump headers and be larger than a few kilobytes.[10][11][2]

### 2. Stop and Backup Data Directory

```bash
# Stop database container
docker compose stop <db-service-name>

# Backup existing data directory
mv ./<data-dir> ./<data-dir>-backup
mkdir ./<data-dir>
```

Replace `<data-dir>` with your actual data directory path from your volume mount.[3][7][6]

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

Look for "database system is ready to accept connections".[7][12]

### 5. Restore Backup

```bash
cat backup.sql | docker exec -i <container-name> psql -U <username> -d postgres
```

**Expected output**: You may see "role already exists" or "database already exists" errors—these are harmless.[13][14][15]

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

Log into your application and verify critical functionality works correctly.[2][4]

## Best Practices

**Test first**: If possible, test the upgrade on a staging environment or copy of your data before production.[4][7][2]

**Read release notes**: Review PostgreSQL release notes for your target version to identify breaking changes.[16][1]

**Keep backups**: Maintain both SQL dump and old data directory for at least one week after successful upgrade.[12][17][4]

**Use same variant**: If upgrading from standard PostgreSQL, use standard; if from Alpine, use Alpine.[18][19]

**Update extensions**: After upgrade, update any PostgreSQL extensions with `ALTER EXTENSION <name> UPDATE;`.[4]

**Refresh statistics**: Run `ANALYZE;` on your databases after restore to update query planner statistics.[2]

**Monitor performance**: Watch application performance for several days after upgrade.[5][4]

## Troubleshooting

### "role already exists" or "database already exists"

**Cause**: PostgreSQL auto-created these from environment variables during initialization.[14][13]

**Solution**: Ignore these errors—the restore continues successfully and populates existing objects with your data.

### Connection refused after restore

**Cause**: Using wrong database name in connection string.[11]

**Solution**: Verify database name matches your `POSTGRES_DB` environment variable using `\l` command.

### Permission denied on data directory

**Cause**: PostgreSQL runs as UID 70 inside containers.[20][21][22]

**Solution**: This is normal—use `docker compose exec` commands to access database, or `sudo` for host filesystem inspection.

### Alpine compatibility issues

**Symptoms**: DNS resolution failures, connection problems, locale errors.[23][24][18]

**Solution**: Switch to standard Debian-based PostgreSQL image (`postgres:18` instead of `postgres:18-alpine`).[6][18]

### Restore hangs or is very slow

**Cause**: Large database taking time to restore.[1][6]

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

**Minor version updates** (e.g., 18.0→18.1): Simply update the image tag and restart—no backup/restore needed.[16][1]

**Major version upgrades** (e.g., 16→17→18): You can skip intermediate versions using this dump/restore method.[1][16]

**Alpine vs Standard**: Alpine images are ~120MB smaller but may have compatibility issues with some applications.[19][25][18]

[1](https://www.postgresql.org/docs/current/upgrading.html)
[2](https://info.enterprisedb.com/rs/069-ALB-339/images/PostgresUpgrade.pdf)
[3](https://www.reddit.com/r/docker/comments/14ucef9/upgrading_postgresql_container_w_persistent_volume/)
[4](https://aws.amazon.com/blogs/database/best-practices-for-upgrading-amazon-rds-to-major-and-minor-versions-of-postgresql/)
[5](https://www.tigerdata.com/blog/read-before-you-upgrade-best-practices-for-choosing-your-postgresql-version)
[6](https://thomasbandt.com/postgres-docker-major-version-upgrade)
[7](https://blog.oxyconit.com/how-to-update-postgres-16-to-17-in-docker/)
[8](https://docs.openappsec.io/deployment-and-upgrade/upgrade-postgres-version-docker-compose)
[9](https://geshan.com.np/blog/2021/12/docker-postgres/)
[10](https://stackoverflow.com/questions/6341321/how-to-check-if-postgresql-backup-was-successful)
[11](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/31134088/4436c58b-e9b0-4635-b30c-9bc36c122bb3/paste.txt)
[12](https://helgeklein.com/blog/upgrading-postgresql-in-docker-container/)
[13](https://www.postgresql.org/docs/current/app-pg-dumpall.html)
[14](https://stackoverflow.com/questions/55619342/postgresql-restore-database-using-dumpall-file)
[15](https://www.postgresql.org/docs/8.1/backup.html)
[16](https://www.postgresql.org/support/versioning/)
[17](https://discourse.joplinapp.org/t/postgres/37747)
[18](https://stackoverflow.com/questions/62333176/docker-difference-postgres12-from-postgres12-alpine)
[19](https://ardentperf.com/2025/04/07/waiting-for-postgres-18-docker-containers-34-smaller/)
[20](https://forums.docker.com/t/data-directory-var-lib-postgresql-data-pgdata-has-wrong-ownership/17963?page=3)
[21](https://stackoverflow.com/questions/56188573/permission-issue-with-postgresql-in-docker-container)
[22](https://github.com/docker-library/postgres/issues/361)
[23](https://github.com/semaphoreui/semaphore/issues/3320)
[24](https://github.com/pgpartman/pg_partman/issues/720)
[25](https://www.byteplus.com/en/topic/556426)
[26](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-perform-major-version-upgrade)
[27](https://stackoverflow.com/questions/62790302/how-to-upgrade-my-postgres-in-docker-container-while-maintaining-my-data-10-3-t)
[28](https://www.pgedge.com/blog/always-online-or-bust-zero-downtime-major-version-postgres-upgrades)
[29](https://damianhodgkiss.com/tutorials/docker-postgres-autoupgrades)
