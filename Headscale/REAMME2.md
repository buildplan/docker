# Deploying Headscale with Headscale-Admin & Headplane via Docker Compose + Traefik

This guide details how to deploy Headscale, a self-hosted Tailscale control server, along with two popular web UIs (Headscale-Admin and Headplane), using Docker Compose. Traefik is used as a reverse proxy to handle HTTPS (via Let's Encrypt) and route traffic appropriately to the different services. Configuration is now enhanced by using environment variables for domain and email settings and a dedicated `tls.yml` for improved TLS security.

**Current Setup Overview (as of [Date of Last Update]):**

* **Headscale API:** Accessible at `https://${HS_URL}` (for clients)
* **Headscale-Admin UI:** Accessible at `https://${HUI_URL}/admin`
* **Headplane UI:** Accessible at `https://${HS_URL}/admin`
* **Traefik:** Handles HTTPS certificates, routing, and security headers.
* **Headplane Integration:** Uses Docker socket integration to manage Headscale.

*(Note: Domain names and email are managed via the `.env` file. See "Environment Variables (.env)" below.)*

## Prerequisites

1.  **Server:** A Linux server (I used Debian 12) accessible from the internet with a public IP address.
2.  **Docker & Docker Compose:** Installed on the server. ([Install Docker](https://docs.docker.com/engine/install/), [Install Docker Compose](https://docs.docker.com/compose/install/))
3.  **Domain Names:** Two domain/subdomain names (e.g., `heads.yourdomain.com` and `hsadmin.yourdomain.com`). You own these domains and can manage their DNS records.
4.  **DNS Records:**
    * An **A record** (for IPv4) or **AAAA record** (for IPv6) for `${HS_URL}` pointing to your server's public IP address.
    * An **A record** (for IPv4) or **AAAA record** (for IPv6) for `${HUI_URL}` pointing to your server's public IP address.
    * **Crucially:** These DNS records must be created and fully propagated *before* you start the Docker Compose setup for the first time, otherwise Let's Encrypt validation will fail.
5.  **Firewall:** The following TCP ports must be **open for inbound traffic** on your server's firewall:
    * **Port 80:** Required by Traefik for the Let's Encrypt HTTP-01 challenge to issue HTTPS certificates.
    * **Port 443:** Required for standard HTTPS traffic to access your services.

## Directory Structure

Create the following directory structure on your server (e.g., in `/opt/headscale-deploy` or `/home/user/appdata/headscale-deploy`):

```
headscale-deploy/
├── docker-compose.yaml
├── .env           # New: Environment variable file
├── headplane/
│   └── config.yaml
├── headscale/
│   ├── config/
│   │   └── config.yaml
│   └── data/       # (Created automatically by Headscale)
└── traefik/
    ├── certificates/ # (Created automatically by Traefik/ACME)
    ├── logs/
    │   └── traefik.log # (Created automatically by Traefik)
    └── tls.yml     # New: Custom TLS options
```

## Environment Variables (.env)

Create a file named `.env` in the root of your `headscale-deploy` directory. This will store your domain names and email, making the `docker-compose.yaml` cleaner and easier to manage.

```
# .env
HS_URL=heads.yourdomain.com
HUI_URL=hsadmin.yourdomain.com
LE_EMAIL=your-email@example.com
```

**-> Remember to replace the placeholder values with your actual domain names and email!**

## Configuration Files

### 1. Headscale (`headscale/config/config.yaml`)

Create this file. You need to configure at least the `server_url` and `listen_addr`. Refer to the [official Headscale sample config](https://github.com/juanfont/headscale/blob/main/config-example.yaml) for all options.

**Minimal Example:**

```yaml
# headscale/config/config.yaml

# The public URL clients will use via Traefik
server_url: "https://${HS_URL}"

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
#    issuer: "[https://your-oidc-provider.com](https://your-oidc-provider.com)"
#    client_id: "your-client-id"
#    client_secret: "<your-client-secret>" # Or use client_secret_path
#    # Create API key with: docker compose exec headscale headscale apikeys create --expiration 999d
#    headscale_api_key: "<your-headscale-api-key-for-oidc-bootstrap>"
#    # Publicly accessible callback URL for Headplane
#    redirect_uri: "https://${HS_URL}/admin/oidc/callback"
```

**-> Remember to generate and set a strong `cookie_secret`!**

### 3. Docker Compose (`docker-compose.yaml`)

This file in the root of your `headscale-deploy` directory defines all the services and their interactions. It now uses environment variables for domain names and email and includes a `secureHeaders` middleware and TLS options.

```yaml
# docker-compose.yaml

services:

    headscale:
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
            - traefik.http.routers.headscale-rtr.rule=Host(`${HS_URL}`)
            - traefik.http.routers.headscale-rtr.priority=90
            - traefik.http.routers.headscale-rtr.entrypoints=websecure
            - traefik.http.routers.headscale-rtr.tls.certresolver=myresolver
            - traefik.http.services.headscale-svc.loadbalancer.server.port=8080
            - traefik.http.routers.headscale-rtr.middlewares=corsHeader@docker,secureHeaders@docker

    headscale-admin:
        image: goodieshq/headscale-admin:0.25.5
        pull_policy: always
        container_name: headscale-admin
        restart: unless-stopped
        labels:
            - traefik.enable=true
            - traefik.http.routers.headscale-admin-rtr.rule=Host(`${HUI_URL}`) && PathPrefix(`/admin`)
            - traefik.http.routers.headscale-admin-rtr.entrypoints=websecure
            - traefik.http.routers.headscale-admin-rtr.tls.certresolver=myresolver
            - traefik.http.services.headscale-admin-svc.loadbalancer.server.port=80
            - traefik.http.routers.headscale-admin-rtr.middlewares=corsHeader@docker,secureHeaders@docker

    headplane:
        image: ghcr.io/tale/headplane:0.5.5
        pull_policy: always
        container_name: headplane
        restart: unless-stopped
        volumes:
            - ./headplane/config.yaml:/etc/headplane/config.yaml:ro # Read-only
            - ./headscale/config:/etc/headscale:ro # Read-only
            - /var/run/docker.sock:/var/run/docker.sock:ro # Read-only
        depends_on:
            - headscale
        labels:
            - traefik.enable=true
            # Rule to match /admin path on the headscale host
            - traefik.http.routers.headplane-rtr.rule=Host(`${HS_URL}`) && PathPrefix(`/admin`)
            # Set priority HIGHER than headscale's router for the same host
            - traefik.http.routers.headplane-rtr.priority=100
            - traefik.http.routers.headplane-rtr.entrypoints=websecure
            - traefik.http.routers.headplane-rtr.tls.certresolver=myresolver
            - traefik.http.services.headplane-svc.loadbalancer.server.port=3000 # Headplane's internal port
            # Apply CORS and security headers
            - traefik.http.routers.headplane-rtr.middlewares=corsHeader@docker,secureHeaders@docker

    traefik:
        image: traefik:v3.3.4
        pull_policy: always
        restart: unless-stopped
        container_name: traefik
        command:
            - --log.filePath=/var/log/traefik.log
            - --accesslog=true
            - --log.level=INFO
            - --ping=true
            - --api=true
            - --api.dashboard=false
            - --providers.docker
            - --entrypoints.web.address=:80
            - --entrypoints.websecure.address=:443
            - --certificatesresolvers.myresolver.acme.tlschallenge=true
            - --certificatesresolvers.myresolver.acme.email=${LE_EMAIL}
            - --certificatesresolvers.myresolver.acme.storage=/certificates/acme.json
            - --global.sendAnonymousUsage=false
            - --entrypoints.websecure.http.tls.options=securetls@file # for TLS
        ports:
            - 80:80
            - 443:443
        volumes:
            - /var/run/docker.sock:/var/run/docker.sock:ro
            - ./traefik/certificates:/certificates
            - ./traefik/logs/traefik.log:/var/log/traefik.log
            - ./traefik/tls.yml:/tls.yml  # Custom TLS
        logging:
            driver: "json-file"
            options:
                max-size: "10m"
                max-file: "3"
        healthcheck:
            test: ["CMD", "wget", "--quiet", "--tries=1", "--output-document=/dev/null", "[http://127.0.0.1:8080/ping](http://127.0.0.1:8080/ping)"]
            interval: 30s
            timeout: 3s
            retries: 3
            start_period: 20s

        labels:
            # CORS middleware for API calls ---
            - traefik.http.middlewares.corsHeader.headers.accesscontrolallowmethods=GET,OPTIONS,PUT
            - traefik.http.middlewares.corsHeader.headers.accesscontrolallowheaders=Authorization,*
            - traefik.http.middlewares.corsHeader.headers.accesscontrolalloworiginlist=https://${HUI_URL},https://${HS_URL} # add in .env
            - traefik.http.middlewares.corsHeader.headers.accesscontrolmaxage=100
            - traefik.http.middlewares.corsHeader.headers.addvaryheader=true

            # --- Redirect ${HUI_URL} root path (/) to /admin ---
            - traefik.http.middlewares.redirect-hui-root-to-admin.redirectregex.regex=^https?://([^/]+)/?$$
            - traefik.http.middlewares.redirect-hui-root-to-admin.redirectregex.replacement=https://$${1}/admin
            - traefik.http.middlewares.redirect-hui-root-to-admin.redirectregex.permanent=true
            - traefik.http.routers.hui-root-redirect.rule=Host(`${HUI_URL}`) && Path(`/`)
            - traefik.http.routers.hui-root-redirect.entrypoints=websecure
            - traefik.http.routers.hui-root-redirect.tls.certresolver=myresolver
            - traefik.http.routers.hui-root-redirect.middlewares=redirect-hui-root-to-admin@docker,secureHeaders@docker

            # --- Redirect ${HS_URL} root path (/) to /admin ---
            - traefik.http.middlewares.redirect-hs-root-to-admin.redirectregex.regex=^https?://([^/]+)/?$$
            - traefik.http.middlewares.redirect-hs-root-to-admin.redirectregex.replacement=https://$${1}/admin
            - traefik.http.middlewares.redirect-hs-root-to-admin.redirectregex.permanent=true
            # Router for the root path of ${HS_URL}
            - traefik.http.routers.hs-root-redirect.rule=Host(`${HS_URL}`) && Path(`/`)
            - traefik.http.routers.hs-root-redirect.priority=95 # Higher than headscale (90), lower than headplane (100)
            - traefik.http.routers.hs-root-redirect.entrypoints=websecure
            - traefik.http.routers.hs-root-redirect.tls.certresolver=myresolver
            - traefik.http.routers.hs-root-redirect.middlewares=redirect-hs-root-to-admin@docker,secureHeaders@docker
            - traefik.http.routers.hs-root-redirect.service=noop@internal

            # --- HSTS Security Headers ---
            - traefik.http.middlewares.secureHeaders.headers.stsSeconds=31536000  # 1 year
            - traefik.http.middlewares.secureHeaders.headers.stsIncludeSubdomains=true
            - traefik.http.middlewares.secureHeaders.headers.stsPreload=true
            - traefik.http.middlewares.secureHeaders.headers.forceSTSHeader=true

            # --- Global Redirect HTTP to HTTPS ---
            - traefik.http.routers.http-catchall.rule=hostregexp(`{host:.+}`)
            - traefik.http.routers.http-catchall.entrypoints=web
            - traefik.http.routers.http-catchall.middlewares=redirect-to-https@docker
            - traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https
            - traefik.http.middlewares.redirect-to-https.redirectscheme.permanent=true

            # --- Enforce Secure Cookies & Enhanced Security ---
            - traefik.http.middlewares.secureHeaders.headers.browserXssFilter=true
            - traefik.http.middlewares.secureHeaders.headers.contentTypeNosniff=true
            - traefik.http.middlewares.secureHeaders.headers.referrerPolicy=same-origin
            - traefik.http.middlewares.secureHeaders.headers.customrequestheaders.X-Forwarded-Proto=https
            - traefik.http.middlewares.secureHeaders.headers.customresponseheaders.Strict-Transport-Security=max-age=31536000; includeSubDomains; preload
            - traefik.http.middlewares.secureHeaders.headers.frameDeny=true  # Prevent Clickjacking
            - traefik.http.middlewares.secureHeaders.headers.permissionsPolicy=geolocation=(), microphone=(), camera=()  # Restrict Browser Features
```

### 4. Traefik TLS Options (`traefik/tls.yml`)

This file defines custom TLS options for Traefik to enhance security.

```yaml
# traefik/tls.yml
tls:
    options:
        securetls:
            minVersion: VersionTLS12
            maxVersion: VersionTLS13  # Explicitly enable TLS 1.3
            cipherSuites:
                # TLS 1.2 ciphers
                - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
                - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
                # TLS 1.3 ciphers
                - TLS_AES_128_GCM_SHA256
                - TLS_AES_256_GCM_SHA384
                - TLS_CHACHA20_POLY1305_SHA256
            curvePreferences:
                - X25519  # Faster and secure (preferred for TLS 1.3)
                - CurveP256  # Widely supported and secure
                - CurveP384  # Stronger fallback
            sniStrict: true  # Require valid SNI (prevent default cert misuse)
```

## Deployment Steps

1.  Navigate to your `headscale-deploy` directory:

    ```bash
    cd /path/to/headscale-deploy
    ```

2.  Ensure all configuration files (`docker-compose.yaml`, `.env`, `headscale/config/config.yaml`, `headplane/config.yaml`, `traefik/tls.yml`) are created and customized as needed (domains, email, secrets).
3.  **Verify DNS records** are pointing correctly to your server IP and have propagated.
4.  **Verify firewall rules** allow inbound traffic on TCP ports 80 and 443.
5.  Start the services:

    ```bash
    docker compose up -d
    ```

6.  Monitor the logs, especially Traefik's for certificate acquisition and Headscale/Headplane for startup messages:

    ```bash
    docker compose logs -f traefik headscale headplane headscale-admin
    ```

    Look for successful ACME certificate messages in the Traefik logs for both domain names.

## Accessing Services

Once deployed successfully:

* **Headscale API:** `https://${HS_URL}` (Use this in Tailscale clients)
* **Headscale-Admin UI:** `https://${HUI_URL}` (Should redirect to `/admin`)
* **Headplane UI:** `https://${HS_URL}/admin`

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
