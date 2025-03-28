# Deploying Headscale with Headscale-Admin & Headplane via Docker Compose + Traefik

This guide details how to deploy Headscale, a self-hosted Tailscale control server, along with two popular web UIs (Headscale-Admin and Headplane), using Docker Compose. Traefik is used as a reverse proxy to handle HTTPS (via Let's Encrypt) and route traffic appropriately to the different services.

**Current Setup Overview (as of March 28, 2025):**

* **Headscale API:** Accessible at `https://heads.yourdomain.com` (for clients)
* **Headscale-Admin UI:** Accessible at `https://hsadmin.yourdomain.com`
* **Headplane UI:** Accessible at `https://heads.yourdomain.com/admin`
* **Traefik:** Handles HTTPS certificates and routing.
* **Headplane Integration:** Uses Docker socket integration to manage Headscale.

*(Note: Replace `heads.yourdomain.com` and `hsadmin.yourdomain.com` with your actual domain names throughout the configuration.)*

## Prerequisites

1.  **Server:** A Linux server (recommended) accessible from the internet.
2.  **Docker & Docker Compose:** Installed on the server. ([Install Docker](https://docs.docker.com/engine/install/), [Install Docker Compose](https://docs.docker.com/compose/install/))
3.  **Domain Names:** Two domain/subdomain names (e.g., `heads.yourdomain.com` and `hsadmin.yourdomain.com`).
4.  **DNS Records:** Pointing both domain names (A or AAAA records) to your server's public IP address. DNS must resolve correctly *before* starting Traefik for Let's Encrypt validation.
5.  **Firewall:** Ports 80 (for HTTP challenge) and 443 (for HTTPS) must be open on your server's firewall.

## Directory Structure

Create the following directory structure on your server (e.g., in `/opt/headscale-deploy` or `/home/user/appdata/headscale-deploy`):

```
headscale-deploy/
├── docker-compose.yaml
├── headplane/
│   └── config.yaml
├── headscale/
│   ├── config/
│   │   └── config.yaml
│   └── data/        # (Created automatically by Headscale)
└── traefik/
    ├── certificates/  # (Created automatically by Traefik/ACME or create)
    └── logs/
        └── traefik.log # (Created automatically by Traefik or run touch traefik.log)
```

## Configuration Files

### 1. Headscale (`headscale/config/config.yaml`)

Create this file. You need to configure at least the `server_url` and `listen_addr`. Refer to the [official Headscale sample config](https://github.com/juanfont/headscale/blob/main/config-example.yaml) for all options.

**Minimal Example:**

```yaml
# headscale/config/config.yaml

# The public URL clients will use via Traefik
server_url: [https://heads.yourdomain.com](https://heads.yourdomain.com)

# Address Headscale listens on *inside* the container network
listen_addr: 0.0.0.0:8080

# Optional: Metrics and debug listener (usually keep default)
metrics_listen_addr: 127.0.0.1:9090

# GRPC listener (usually keep default)
grpc_listen_addr: 0.0.0.0:50443
grpc_allow_insecure: false # Use true ONLY if needed for specific tooling, usually false

# Database configuration
db_type: sqlite3
db_path: /var/lib/headscale/db.sqlite

# Other settings (TLS, OIDC, Logging, etc.) can be configured as needed.
# Ensure TLS is disabled here as Traefik handles it:
tls_letsencrypt_hostname: ""
tls_letsencrypt_listen: ""
tls_cert_path: ""
tls_key_path: ""

# Recommended: Define IP prefixes for your Tailscale network
ip_prefixes:
  - fd7a:115c:a1e0::/48
  - 100.64.0.0/10
```

### 2. Headplane (`headplane/config.yaml`)

Create this file to configure the Headplane UI.

```yaml
# headplane/config.yaml

server:
  host: "0.0.0.0"
  port: 3000 # Headplane listens on this port *inside* the container

  # !!! IMPORTANT: Generate a secure 32-character random string !!!
  # Use: openssl rand -base64 24 (or similar) and paste the result below
  cookie_secret: "REPLACE_THIS_WITH_A_32_CHAR_SECURE_SECRET"

  # Use true because Traefik is handling HTTPS
  cookie_secure: true

headscale:
  # URL Headplane uses to reach Headscale *within the Docker network*
  url: "http://headscale:8080"

  # Path to the Headscale config *inside the Headplane container*
  # Must match the volume mount in docker-compose.yaml
  config_path: "/etc/headscale/config.yaml"

  # Keep validation enabled
  config_strict: true

# Integration via Docker
integration:
  docker:
    enabled: true
    # The container name of your Headscale service
    container_name: "headscale"
    # Path to the Docker socket *inside the Headplane container*
    socket: "unix:///var/run/docker.sock"
  kubernetes:
    enabled: false
  proc:
    enabled: false

# Optional OIDC Configuration (Uncomment and configure if needed)
# oidc:
#   issuer: "[https://your-oidc-provider.com](https://www.google.com/search?q=https://your-oidc-provider.com)"
#   client_id: "your-client-id"
#   client_secret: "<your-client-secret>" # Or use client_secret_path
#   # Create API key with: docker compose exec headscale headscale apikeys create --expiration 999d
#   headscale_api_key: "<your-headscale-api-key-for-oidc-bootstrap>"
#   # Publicly accessible callback URL for Headplane
#   redirect_uri: "[https://heads.yourdomain.com/admin/oidc/callback](https://www.google.com/search?q=https://heads.yourdomain.com/admin/oidc/callback)"
```

**-> Remember to generate and set a strong `cookie_secret`!**

### 3. Docker Compose (`docker-compose.yaml`)

Create this file in the root of your `headscale-deploy` directory. This defines all the services and their interactions.

```yaml
# docker-compose.yaml

services:

  headscale:
    # Use specific, compatible versions
    image: headscale/headscale:0.25.1
    pull_policy: always
    container_name: headscale
    restart: unless-stopped
    command: serve
    volumes:
      # Mount config and data directories from host
      - ./headscale/config:/etc/headscale
      - ./headscale/data:/var/lib/headscale
    labels:
      - traefik.enable=true
      # Route requests for heads.yourdomain.com (except /admin)
      - traefik.http.routers.headscale-rtr.rule=Host(`heads.yourdomain.com`)
      # Priority LOWER than Headplane's router for the same host
      - traefik.http.routers.headscale-rtr.priority=90
      - traefik.http.routers.headscale-rtr.entrypoints=websecure
      - traefik.http.routers.headscale-rtr.tls.certresolver=myresolver
      - traefik.http.services.headscale-svc.loadbalancer.server.port=8080 # Headscale internal port
      - traefik.http.routers.headscale-rtr.middlewares=corsHeader@docker

  headscale-admin:
    # Use specific, compatible versions
    image: goodieshq/headscale-admin:0.25.5
    pull_policy: always
    container_name: headscale-admin
    restart: unless-stopped
    labels:
      - traefik.enable=true
      # Route requests for [hsadmin.yourdomain.com/admin](https://www.google.com/search?q=https://hsadmin.yourdomain.com/admin)
      - traefik.http.routers.headscale-admin-rtr.rule=Host(`hsadmin.yourdomain.com`) && PathPrefix(`/admin`)
      - traefik.http.routers.headscale-admin-rtr.entrypoints=websecure
      - traefik.http.routers.headscale-admin-rtr.tls.certresolver=myresolver
      - traefik.http.services.headscale-admin-svc.loadbalancer.server.port=80 # headscale-admin internal port
      - traefik.http.routers.headscale-admin-rtr.middlewares=corsHeader@docker

  headplane:
    # Use specific versions
    image: ghcr.io/tale/headplane:0.5.5
    pull_policy: always
    container_name: headplane
    restart: unless-stopped
    volumes:
      # Mount config files and docker socket (read-only where possible)
      - ./headplane/config.yaml:/etc/headplane/config.yaml:ro
      - ./headscale/config:/etc/headscale:ro # Mount Headscale config read-only
      - /var/run/docker.sock:/var/run/docker.sock:ro
    depends_on:
      - headscale # Start after headscale
    labels:
      - traefik.enable=true
      # Route requests for [heads.yourdomain.com/admin](https://heads.yourdomain.com/admin)
      - traefik.http.routers.headplane-rtr.rule=Host(`heads.yourdomain.com`) && PathPrefix(`/admin`)
      # Priority HIGHER than headscale's router for the same host
      - traefik.http.routers.headplane-rtr.priority=100
      - traefik.http.routers.headplane-rtr.entrypoints=websecure
      - traefik.http.routers.headplane-rtr.tls.certresolver=myresolver
      - traefik.http.services.headplane-svc.loadbalancer.server.port=3000 # Headplane internal port
      - traefik.http.routers.headplane-rtr.middlewares=corsHeader@docker

  traefik:
    # Use a specific, stable version
    image: traefik:v3.1.4 # Latest at the time of writing.
    pull_policy: always
    container_name: traefik
    restart: unless-stopped
    command:
      - --log.filePath=/var/log/traefik.log
      - --accesslog=true
      - --log.level=INFO # Change to DEBUG for troubleshooting
      - --api=true
      - --api.dashboard=false # Keep false unless secured
      - --providers.docker
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      # Let's Encrypt configuration - REPLACE EMAIL
      - --certificatesresolvers.myresolver.acme.tlschallenge=true
      - --certificatesresolvers.myresolver.acme.email=your-email@example.com
      - --certificatesresolvers.myresolver.acme.storage=/certificates/acme.json
      - --global.sendAnonymousUsage=false
    ports:
      # Expose HTTP and HTTPS entrypoints
      - 80:80
      - 443:443
    volumes:
      # Mount docker socket, certificates volume, and log file
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik/certificates:/certificates
      - ./traefik/logs/traefik.log:/var/log/traefik.log
    labels:
      # --- CORS Middleware Definition ---
      # Allows cross-origin requests from the UI domains to the API
      - traefik.http.middlewares.corsHeader.headers.accesscontrolallowmethods=GET,OPTIONS,PUT
      - traefik.http.middlewares.corsHeader.headers.accesscontrolallowheaders=Authorization,*
      - traefik.http.middlewares.corsHeader.headers.accesscontrolalloworiginlist=[https://hsadmin.yourdomain.com](https://hsadmin.yourdomain.com),[https://heads.yourdomain.com](https://heads.yourdomain.com)
      - traefik.http.middlewares.corsHeader.headers.accesscontrolmaxage=100
      - traefik.http.middlewares.corsHeader.headers.addvaryheader=true

      # --- Redirect hsadmin.yourdomain.com root path (/) to /admin ---
      - traefik.http.middlewares.redirect-hsadmin-root-to-admin.redirectregex.regex=^https?://([^/]+)/?$$
      - traefik.http.middlewares.redirect-hsadmin-root-to-admin.redirectregex.replacement=https://$${1}/admin
      - traefik.http.middlewares.redirect-hsadmin-root-to-admin.redirectregex.permanent=true
      - traefik.http.routers.hsadmin-root-redirect.rule=Host(`hsadmin.yourdomain.com`) && Path(`/`)
      - traefik.http.routers.hsadmin-root-redirect.entrypoints=websecure
      - traefik.http.routers.hsadmin-root-redirect.tls.certresolver=myresolver
      - traefik.http.routers.hsadmin-root-redirect.middlewares=redirect-hsadmin-root-to-admin@docker

      # --- Global Redirect HTTP to HTTPS ---
      - traefik.http.routers.http-catchall.rule=hostregexp(`{host:.+}`)
      - traefik.http.routers.http-catchall.entrypoints=web
      - traefik.http.routers.http-catchall.middlewares=redirect-to-https@docker
      - traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https
      - traefik.http.middlewares.redirect-to-https.redirectscheme.permanent=true
```

**-> Remember to replace:**
* `heads.yourdomain.com`
* `hsadmin.yourdomain.com`
* `your-email@example.com` (Use your real email for Let's Encrypt registration/renewal notices)
* Consider updating image tags (`headscale:`, `headscale-admin:`, `headplane:`, `traefik:`) to desired stable versions.

## Deployment Steps

1.  Navigate to your `headscale-deploy` directory:
    ```bash
    cd /path/to/headscale-deploy
    ```
2.  Ensure all configuration files (`docker-compose.yaml`, `headscale/config/config.yaml`, `headplane/config.yaml`) are created and customized as needed (domains, email, secrets).
3.  Ensure your DNS records are pointing correctly to your server IP.
4.  Ensure ports 80 and 443 are open in your firewall.
5.  Start the services:
    ```bash
    docker compose up -d
    ```
6.  Monitor the logs, especially Traefik's for certificate acquisition and Headscale/Headplane for startup messages:
    ```bash
    docker compose logs -f traefik headscale headplane headscale-admin
    ```
    Look for successful ACME certificate messages in the Traefik logs.

## Accessing Services

Once deployed successfully:

* **Headscale API:** `https://heads.yourdomain.com` (Use this in Tailscale clients)
* **Headscale-Admin UI:** `https://hsadmin.yourdomain.com` (Should redirect to `/admin`)
* **Headplane UI:** `https://heads.yourdomain.com/admin`

## Important Notes

* **Headscale TLS Warning:** You will likely see a `WRN Listening without TLS but ServerURL does not start with http://` in the `headscale` logs. This is **normal and expected** in this setup because Traefik handles TLS. Ignore this warning.
* **Headplane Login:** If not using OIDC, Headplane will require a Headscale API key for initial login and subsequent administrative actions. Create one *after* startup using:
    ```bash
    docker compose exec headscale headscale apikeys create --expiration 999d
    ```
    Copy the generated key.
* **Backups:** Regularly back up your persistent volumes, especially `./headscale/data` (contains the database) and `./traefik/certificates`.
* **Security:** Ensure your `headplane/config.yaml` `cookie_secret` is strong and kept private. Secure access to your server and the Docker socket. If enabling the Traefik dashboard, secure it properly with authentication.
* **Updates:** Periodically update the image versions in your `docker-compose.yaml` for security patches and new features, ensuring compatibility between Headscale and the UIs.

## Customization

* **Versions:** Change the image tags in `docker-compose.yaml` to use different versions of Headscale, Headplane, Headscale-Admin, or Traefik. Check for compatibility.
* **OIDC:** Configure the `oidc:` section in `headplane/config.yaml` for single sign-on.
* **Headscale Config:** Explore `headscale/config/config.yaml` for advanced features like ACLs, DNS configuration, etc.
* **Traefik:** Explore Traefik documentation for advanced routing, middlewares, authentication, etc.

```
