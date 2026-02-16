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

- `--user 0:0` and `-w /data`: Fixes the "Permission Denied" error.
- `--no-interactive`: Prevents the command from hanging/crashing.
- Get the runner registration toke from you main forgejo server - *settings > Actions > Runners > Create new runner*
- Update `FORGEJO_REGISTRATION_TOKEN` and `remote-vps-name` in the command below

```bash
sudo docker run --rm --user 0:0 \
  -v $(pwd)/runner/data:/data \
  -w /data \
  code.forgejo.org/forgejo/runner:12.6.4 \
  forgejo-runner register \
  --no-interactive \
  --instance https://git.alisufyan.cloud \
  --token FORGEJO_REGISTRATION_TOKEN \
  --name remote-vps-name \
  --labels "ubuntu-latest:docker://ghcr.io/catthehacker/ubuntu:act-24.04,docker:docker://node:20-bullseye"
```

**Fix Permissions:**

The command above creates a `.runner` file owned by root. Change it back to your user so the docker-compose service can read it:

```bash
sudo chown -R $USER:$USER $(pwd)/runner/data
```

## 3. Configuration & Deployment

Create your `docker-compose.yml` and `config.yml`.

### docker-compose.yml

```yaml
services:
  forgejo-runner:
    image: code.forgejo.org/forgejo/runner:12
    container_name: forgejo-runner
    user: 1002:1002 # check with 'id' on the system and change
    group_add:
      - "988" # 'id' should show docker group id as well
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

### config.yml (Key Changes)

Ensure the `container: network` is set to `bridge` since the remote VPS doesn't have access to the server's internal Docker network.

```yaml
log:
  level: info
  job_level: info
 
runner:
  file: .runner
  capacity: 2
  envs:
    A_TEST_ENV_NAME_1: a_test_env_value_1
    A_TEST_ENV_NAME_2: a_test_env_value_2
  env_file: .env
  timeout: 3h
  shutdown_timeout: 3h
  insecure: false
  fetch_timeout: 5s
  fetch_interval: 2s
  report_interval: 1s
  labels:
    - "ubuntu-latest-2:docker://docker.gitea.com/runner-images:ubuntu-latest"
    - "ubuntu-latest:docker://ghcr.io/catthehacker/ubuntu:act-24.04"
    - "ubuntu-22.04-2:docker://ghcr.io/catthehacker/ubuntu:act-22.04"
    - "ubuntu-full-2:docker://ghcr.io/catthehacker/ubuntu:full-24.04"
    - "ubuntu-latest-2-js:docker://ghcr.io/catthehacker/ubuntu:js-latest"
    - "debian-bookworm-2:docker://debian:bookworm"
    - "debian-trixie-slim-2:docker://debian:trixie-slim"
    - "alpine-3.20-2:docker://alpine:3.20"
    - "minimal-node-2:docker://node:24-slim"
    - "shellcheck-2:docker://koalaman/shellcheck-alpine:stable"
 
cache:
  enabled: true
  port: 8686
  dir: "/data/cache"
  secret: "l2kEV9YgppCB3ANIw15kHDXVapz9AB2zKztbbaLnVipztB2GS73U6RDB4ZYrqoKy" # some random long string
  host: "forgejo-runner"
  proxy_port: 0
 
container:
  network: bridge  # Crucial for remote systems
  network: bridge
  enable_ipv6: false
  privileged: false
  options: "--group-add 988" # Check 'getent group docker' on the new VPS
  workdir_parent:
  valid_volumes: ["**"]
  docker_host: "automount"
```

* * *

## 4. Security & Networking (The "Hidden" Requirements)

If your runner is "Idle" but jobs keep failing with connection timeouts, check these three areas:

### A. Reverse Proxy (Nginx/Traefik)

If Forgejo is behind a reverse proxy, the proxy must allow long-lived connections (WebSockets/Long Polling).

- Ensure your proxy doesn't have a very short timeout (e.g., 60s).
- The runner makes a "long-poll" request to the server; if the proxy cuts it off, the runner will cycle constantly.
    

### B. CrowdSec / Fail2Ban Whitelisting

Because the runner makes thousands of requests per day to `git.domain.com`, your security tools might flag it as a "DDoS" or "Bot."

**On your Forgejo Server/Proxy VPS:**

- **CrowdSec:** Add the Remote Runner's IP to the whitelist.
    
    ```bash
    # Edit /etc/crowdsec/parsers/s02-enrich/whitelists.yaml
    name: forgejo-whitelist
    description: "Whitelist remote runners"
    whitelist:
      reason: "remote forgejo runner"
      ip:
        - "RUNNER_VPS_IP"
    ```
    
- **Fail2Ban:** Add the IP to the `ignoreip` list in `jail.local`.
    
    ```toml
    [DEFAULT]
    ignoreip = 127.0.0.1/8 ::1 RUNNER_VPS_IP
    ```
    

### C. Firewall (UFW/Iptables)

The Remote Runner only needs **OUTBOUND** access to the server on Port 443.

However, the **Forgejo Server** must allow that specific IP. If you have strict UFW rules:

```bash
sudo ufw allow from RUNNER_VPS_IP to any port 443 proto tcp
```

* * *

## 5. ARM64 vs x86_64 Awareness

- **Renovate:** Works natively on both.
    
- **Docker Builds:** Use `docker/setup-qemu-action@v3` and `docker/setup-buildx-action@v3` in your workflows to ensure that when an ARM runner builds an image, it includes the `amd64` version (and vice versa).
    

## 6. Maintenance

Every few months, clean up the runner VPS to prevent disk bloat from old Docker build layers:

```bash
docker system prune -f
```

**Final Check:** Once deployed, go to **Site Admin > Actions > Runners**. If the dot is **Green (Idle)**, the handshake is complete and the runner is ready for jobs.
