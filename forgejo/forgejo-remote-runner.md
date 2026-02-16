# Forgejo Remote Runner Deployment Guide

## 1. Prepare the Remote VPS

Log into the new system and ensure Docker is installed and the directory structure is ready.

```bash
# Create the directory structure
mkdir -p ~/apps/forgejo-runner/runner/data
mkdir -p ~/apps/forgejo-runner/runner/cache
cd ~/apps/forgejo-runner
```

## 2. Register the Runner

The runner must be registered with the server to generate a `.runner` credential file.

**Critical Flags:**

* `--user 0:0` and `-w /data`: Forces the container to run as root so it has permission to write the `.runner` file to your host volume.
* `--no-interactive`: Mandatory for running registration inside a non-tty Docker container.
* **Token:** Get this from your Forgejo instance: *Site Admin > Actions > Runners > Create new runner*.

```bash
sudo docker run --rm --user 0:0 \
  -v $(pwd)/runner/data:/data \
  -w /data \
  code.forgejo.org/forgejo/runner:12.6.4 \
  forgejo-runner register \
  --no-interactive \
  --instance https://git.domain.tld \
  --token YOUR_REGISTRATION_TOKEN \
  --name remote-vps-name \
  --labels "ubuntu-latest:docker://ghcr.io/catthehacker/ubuntu:act-24.04,docker:docker://node:20-bullseye"
```

**Fix Ownership:**
The command above creates a `.runner` file owned by `root`. Change it back to your user so the runner service can manage it:

```bash
sudo chown -R $USER:$USER $(pwd)/runner/data
```

## 3. Configuration & Deployment

### Step A: Identify GIDs

On the **new VPS**, find your User ID and the Docker Group ID. These are often different on every provider.

```bash
id          # Look for uid (e.g., 1002)
getent group docker | cut -d: -f3  # Look for docker gid (e.g., 988)
```

### Step B: docker-compose.yml

```yaml
services:
  forgejo-runner:
    image: code.forgejo.org/forgejo/runner:12
    container_name: forgejo-runner
    user: 1002:1002 # Use the IDs found in Step A
    group_add:
      - "988"       # Use the Docker GID found in Step A
    expose:
      - "8686"
    environment:
      - DOCKER_CONFIG=/runner_creds
    volumes:
      - ./runner/data:/data
      - ./runner/cache:/data/cache
      - ./runner/data/config.yml:/data/config.yml:ro
      - /var/run/docker.sock:/var/run/docker.sock
    restart: 'unless-stopped'
    command: >
      /bin/sh -c "forgejo-runner daemon --config /data/config.yml"
    logging:
      driver: "json-file"
      options: { max-size: "5m", max-file: "3" }
```

### Step C: config.yml

Ensure `network: bridge` is set. Remote runners cannot use internal Docker networks of the Forgejo server.

```yaml
log:
  level: info
  job_level: info

runner:
  file: .runner
  capacity: 2
  labels:
    - "ubuntu-latest-2:docker://ghcr.io/catthehacker/ubuntu:act-24.04"
    - "ubuntu-latest:docker://ghcr.io/catthehacker/ubuntu:act-24.04"
    - "shellcheck-2:docker://koalaman/shellcheck-alpine:stable"

cache:
  enabled: true
  port: 8686
  dir: "/data/cache"
  secret: "long-random-string-here"
  host: "forgejo-runner"

container:
  network: bridge  # Crucial for remote systems
  enable_ipv6: false
  privileged: false
  options: "--group-add 988" # Must match the GID in docker-compose.yml
  workdir_parent:
  valid_volumes: ["**"]
  docker_host: "automount"
```

---

## 4. Security & Networking

### A. Reverse Proxy Timeouts

If Forgejo is behind Nginx/Traefik, ensure proxy timeouts are high (e.g., 300s). Short timeouts will cause the runner to disconnect constantly during long-polling.

### B. CrowdSec / Fail2Ban Whitelisting

The runner hits your server API frequently. **Whitelist the Runner IP** on the Forgejo Server:

**CrowdSec:**

Add to `/etc/crowdsec/parsers/s02-enrich/whitelists.yaml`:

```yaml
name: runner-whitelist
description: "Forgejo Remote Runner"
whitelist:
  reason: "internal runner"
  ip: ["RUNNER_VPS_IP"]
```

**Fail2Ban:**

Add to `[DEFAULT]` in `jail.local`:

```ini
ignoreip = 127.0.0.1/8 ::1 RUNNER_VPS_IP
```

### C. Firewall (UFW)

```bash
sudo ufw allow from RUNNER_VPS_IP to any port 443 proto tcp
```

---

## 5. Architecture (ARM64 vs x86)

* **Renovate:** Works natively on ARM64; no changes needed.
* **Docker Builds:** Use `docker/setup-qemu-action@v3` in workflows to ensure ARM64 runners can build `amd64` images (and vice versa).

## 6. Maintenance & Validation

**Start the runner:**

```bash
docker compose up -d
```

**Verify Connection:**

1. Check Logs: `docker compose logs -f`
2. Check Forgejo UI: **Site Admin > Actions > Runners**. Look for a **Green (Idle)** status for your new runner name.
3. Prune old build layers monthly: `docker system prune -f`
