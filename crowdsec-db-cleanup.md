# CrowdSec Database Maintenance Guide (Docker / Alpine)

**The Problem:** When CrowdSec's SQLite database gets bloated (e.g., > 500MB) due to logging thousands of attacks, local API queries slow down significantly. This causes timeout errors (like `timeout of 2000ms exceeded`) in Node.js or other connected bouncers.

**The Solution:** Backup the database, flush old alert logs, and run an SQLite `VACUUM` to rebuild and defragment the file.

### Step 1: Check Current Database Size

Check how much disk space the database is currently using to see if it needs maintenance:

```bash
docker exec crowdsec ls -lh /var/lib/crowdsec/data/crowdsec.db
```

### Step 2: Backup the Database (Choose One Method)

Stop the container to ensure the database isn't locked or actively writing to the `-wal` files:

```bash
docker stop crowdsec
```

**Method A (Direct on Host):** *(Use `cp -a` to archive the entire directory, preserving permissions and capturing all `.db`, `-wal`, and `-shm` files)*

```bash
sudo cp -a /path/to/crowdsec/data/ /path/to/crowdsec/data_backup/
```

**Method B (Using Docker Volumes - Safest):**
*(This mounts your current folder as `/backup` and archives the entire data folder inside the container)*

```bash
docker run --rm --volumes-from crowdsec -v $(pwd):/backup alpine \
  cp -a /var/lib/crowdsec/data/ /backup/crowdsec_data_backup/
```

Start the container again so we can use the CLI for the next steps:

```bash
docker start crowdsec
```

### Step 3: Flush Old Alert History

Delete historical alerts (logs of *why* an IP was banned) to shed dead weight. This command deletes logs older than 1 week (168 hours).

> _**Note:** This preserves your active bans/decisions; it only deletes the history._

```bash
docker exec crowdsec cscli alerts flush --max-age 168h
```

### Step 4: Stop CrowdSec (Crucial)

SQLite requires an exclusive lock on the file to perform a `VACUUM`. If CrowdSec is running, you will get a `database is locked (5)` error.

```bash
docker stop crowdsec
```

### Step 5: Vacuum and Optimize

Spin up a temporary, lightweight Alpine container attached to CrowdSec's database volume. This command installs SQLite, rebuilds the database from scratch to reclaim empty space, optimizes the indexes, and then automatically deletes the temporary container (`--rm`).

> _**Note:** Depending on the file size, this may take 30–60 seconds to finish. Let it run!_

```bash
docker run --rm --volumes-from crowdsec alpine sh -c \
  "apk add --no-cache sqlite && sqlite3 /var/lib/crowdsec/data/crowdsec.db 'VACUUM; PRAGMA optimize;'"
```

### Step 6: Start CrowdSec

Start the container back up so it loads the fresh, optimized database into RAM:

```bash
docker start crowdsec
```

### Step 7: Verify

Check the file size again. It should be drastically smaller, and your local API queries will be back to answering in milliseconds.

```bash
docker exec crowdsec ls -lh /var/lib/crowdsec/data/crowdsec.db
```
