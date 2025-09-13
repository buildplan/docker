# Self-Hosted Forgejo with CI/CD Runner using Docker Compose

This guide documents a setup for a self-hosted Forgejo Git service with an integrated CI/CD runner. The entire stack is managed with Docker Compose and uses the host's Docker socket for running jobs, which is simpler and more efficient than a Docker-in-Docker approach for a single-server environment.

-----

## Prerequisites

1.  A Linux server with **Docker** and **Docker Compose** installed.
2.  A domain name pointed at your server's IP address (e.g., `git.yourdomain.com`).
3.  The Group ID (GID) of the `docker` group on your host machine. Find it by running this command on your server and noting the number:
    ```bash
    getent group docker | cut -d: -f3
    ```

-----

## Directory Structure

Your final directory structure will look like this:

```
forgejo/
├── .env
├── docker-compose.yml
├── forgejo-data/
└── runner/
    └── data/
```

-----

## Configuration Files

You will need to create two files: `.env` and `docker-compose.yml`.

### 1\. The `.env` File

This file stores all your secrets and version tags. Create a file named `.env` in the `forgejo/` directory.

```env
# .env

# Version Tags
SERVER_VER=12
DB_VER=17-alpine
RUNNER_VER=9

# Database Credentials
POSTGRES_USER=forgejo
POSTGRES_PASSWORD=a_very_strong_and_secret_password
POSTGRES_DB=forgejo

# Forgejo URLs (Replace with your actual domain)
FORGEJO_ROOT_URL=https://git.yourdomain.com
FORGEJO_SSH_DOMAIN=git.yourdomain.com
```

### 2\. The `docker-compose.yml` File

This file defines all the services. Create a file named `docker-compose.yml` in the `forgejo/` directory.

```yaml
# docker-compose.yml

networks:
  forgejo:
    external: false

services:
  # --- forgejo server ---
  forgejo-server:
    image: codeberg.org/forgejo/forgejo:${SERVER_VER:-12}
    container_name: forgejo-server
    environment:
      - USER_UID=1001
      - USER_GID=1001
      - FORGEJO__actions__ENABLED=true
      - FORGEJO__database__DB_TYPE=postgres
      - FORGEJO__database__HOST=forgejo-db:5432
      - FORGEJO__database__NAME=${POSTGRES_DB}
      - FORGEJO__database__USER=${POSTGRES_USER}
      - FORGEJO__database__PASSWD=${POSTGRES_PASSWORD}
      - FORGEJO__server__ROOT_URL=${FORGEJO_ROOT_URL}
      - FORGEJO__server__SSH_DOMAIN=${FORGEJO_SSH_DOMAIN}
      - FORGEJO__server__SSH_PORT=555
      - FORGEJO__server__SSH_LISTEN_PORT=22
    restart: unless-stopped
    networks:
      - forgejo
    volumes:
      - ./forgejo-data:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro
    ports:
      # Map 3000 to localhost and any other specific IPs you need
      - "127.0.0.1:3009:3000"
      - "555:22"
    depends_on:
      forgejo-db:
        condition: service_healthy
    logging:
      driver: "json-file"
      options: { max-size: "5m", max-file: "3" }

  # --- forgejo DB ---
  forgejo-db:
    image: postgres:${DB_VER:-17-alpine}
    container_name: forgejo-db
    restart: unless-stopped
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}
    networks:
      - forgejo
    volumes:
      - ./forgejo-db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTG-RES_USER} -d ${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5
    logging:
      driver: "json-file"
      options: { max-size: "5m", max-file: "3" }

  # --- forgejo runner ---
  forgejo-runner:
    image: code.forgejo.org/forgejo/runner:${RUNNER_VER:-9}
    depends_on:
      forgejo-server:
        condition: service_started
    container_name: forgejo-runner
    networks:
      - forgejo
    user: 1001:1001
    group_add:
      # GID of the 'docker' group on the host. Find with:
      # getent group docker | cut -d: -f3
      - <YOUR_DOCKER_GROUP_ID>
    volumes:
      - ./runner/data:/data
      - ./runner/data/config.yml:/data/config.yml:ro
      - /var/run/docker.sock:/var/run/docker.sock
    restart: unless-stopped
    command: '/bin/sh -c "sleep 5; forgejo-runner daemon --config /data/config.yml"'
    logging:
      driver: "json-file"
      options: { max-size: "5m", max-file: "3" }
```

**Remember to replace `<YOUR_DOCKER_GROUP_ID>` with the number from the prerequisites.**

-----

## Setup Instructions

This setup involves a multi-stage process to correctly register the runner.

### Step 1: Initial Runner Registration

The runner container needs a `.runner` file to start, but that file can only be created by the `register` command. To break this catch-22, we temporarily change its startup command.

1.  **Modify `docker-compose.yml` for registration:**
    Temporarily change the `command` in the `forgejo-runner` service to keep it alive without starting the daemon.
    ```yaml
    # In docker-compose.yml
    command: 'sleep infinity'
    ```
2.  **Start the stack:**
    ```bash
    docker compose up -d
    ```
3.  **Get a registration token:**
    Go to your Forgejo UI, click your profile picture -\> **Settings** -\> **Actions** -\> **Runners**, and click **Create new runner**. Copy the token.
4.  **Register the runner:**
    ```bash
    docker compose exec forgejo-runner forgejo-runner register
    ```
    Follow the prompts, pasting the token when asked.

### Step 2: Final Configuration

Now that the runner is registered, we can apply the final, correct configuration.

1.  **Stop the stack:**
    ```bash
    docker compose down
    ```
2.  **Create the runner's `config.yml`:**
    This file tells the runner to place job containers on the shared network.
    ```bash
    # Find your full network name
    docker network ls | grep forgejo
    # It will be something like forgejo_forgejo

    # Create the config file
    nano ~/forgejo/runner/data/config.yml
    ```
    Add this content to the file, using your full network name:
    ```yaml
    # ~/forgejo/runner/data/config.yml
    container:
      network: forgejo_forgejo
    ```
3.  **Edit the `.runner` file for internal networking:**
    The registration process used your public URL. We must change it to the internal Docker service name.
    ```bash
    nano ~/forgejo/runner/data/.runner
    ```
    Find the `address` line and change it:
      * **From:** `"address": "https://git.yourdomain.com",`
      * **To:** `"address": "http://forgejo-server:3000",`
4.  **Restore the final `command` in `docker-compose.yml`:**
    Change the `command` in the `forgejo-runner` service back to the one that starts the daemon.
    ```yaml
    # In docker-compose.yml
    command: '/bin/sh -c "sleep 5; forgejo-runner daemon --config /data/config.yml"'
    ```

### Step 3: Final Startup

Apply the final changes and start the full stack.

```bash
docker compose up -d
```

-----

## Verification and Usage

Your Forgejo instance and runner are now fully configured\!

  * **Verify:** Go to your Forgejo "Runners" settings page. You should see your new runner with a green "Idle" status.

  * **Usage:** To use your runner, create a `.forgejo/workflows/ci.yml` file in one of your repositories:

    ```yaml
    # .forgejo/workflows/ci.yml
    name: CI
    on: [push]

    jobs:
      build:
        # This label comes from the default registration
        runs-on: docker

        steps:
          - name: Check out repository code
            uses: actions/checkout@v4
          - name: Test command
            run: echo "🎉 Workflow is running successfully on a self-hosted runner!"
    ```

Push this file, and the workflow will run on your new setup.
