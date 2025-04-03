# Deploying Headscale with Headscale-Admin & Headplane via Docker Compose + Traefik

This guide details how to deploy [Headscale](https://github.com/juanfont/headscale), a self-hosted [Tailscale](https://tailscale.com/kb) control server, along with two popular web UIs ([Headscale-Admin](https://github.com/GoodiesHQ/headscale-admin) and [Headplane](https://github.com/tale/headplane)), using Docker Compose. Traefik is used as a reverse proxy to handle HTTPS (via Let's Encrypt) and route traffic appropriately to the different services. This setup uses environment variables for domain and email settings and a dedicated `tls.yml` for improved TLS security. **OIDC (OpenID Connect) is now integrated for Headplane authentication.**

**Current Setup Overview:**

* **Headscale API:** Accessible at `https://${HS_URL}` (for clients)
* **Headscale-Admin UI:** Accessible at `https://${HUI_URL}` (Redirects to `/admin`)
* **Headplane UI:** Accessible at `https://${HS_URL}/admin`
* **Traefik:** Handles HTTPS certificates, routing, security headers, and authentication.
* **Headplane Integration:** Uses Docker socket integration to manage Headscale.
* **Headplane Authentication:** Uses OIDC for user authentication.

*(Note: Domain names and email are managed via the `.env` file. See "Environment Variables (.env)" below.)*

## Prerequisites

1.  **Server:** A Linux server (recommended) accessible from the internet with a public IP address.
2.  **Docker & Docker Compose:** Installed on the server. ([Install Docker](https://docs.docker.com/engine/install/), [Install Docker Compose](https://docs.docker.com/compose/install/))
3.  **Domain Names:** Two domain/subdomain names (e.g., `heads.yourdomain.com` and `hsadmin.yourdomain.com`). You own these domains and can manage their DNS records.
4.  **DNS Records:**
    * An **A record** (for IPv4) or **AAAA record** (for IPv6) for `${HS_URL}` pointing to your server's public IP address.
    * An **A record** (for IPv4) or **AAAA record** (for IPv6) for `${HUI_URL}` pointing to your server's public IP address.
    * **Crucially:** These DNS records must be created and fully propagated *before* you start the Docker Compose setup for the first time, otherwise Let's Encrypt validation will fail.
5.  **Firewall:** The following TCP ports must be **open for inbound traffic** on your server's firewall:
    * **Port 80:** Required by Traefik for the Let's Encrypt HTTP-01 challenge to issue HTTPS certificates.
    * **Port 443:** Required for standard HTTPS traffic to access your services.
6.  **OIDC Provider:** You need an OIDC provider (e.g., Google, Auth0) and the necessary credentials (client ID, client secret).

## Directory Structure

Create the following directory structure on your server (e.g., in `/opt/headscale-deploy` or `/home/user/appdata/headscale-deploy`):

```
headscale-deploy/
├── .env           # Environment variable file
├── docker-compose.yaml
├── headplane/
│   ├── config.yaml
│   ├── secrets/
│   │   └── oidc_client_secret
│   └── users/
│       └── users.json
├── headscale/
│   ├── config/
│   │   └── config.yaml
│   └── data/
└── traefik/
    ├── auth/
    │   └── users.htpasswd
    ├── certificates/
    │   └── acme.json
    ├── logs/
    │   └── traefik.log
    └── tls.yml
```

## File & Directory Notes:

* **`headscale-deploy/`**
    * Root directory for the Headscale deployment project.
* **`headscale-deploy/.env`**
    * Stores environment variables (e.g., domain names, email for ACME, API keys).
    * **Sensitive** - Should NOT be committed to Git.
* **`headscale-deploy/docker-compose.yaml`**
    * Defines the services (Headscale, Traefik, Headplane), volumes, networks, resource limits, etc., for Docker Compose.
* **`headscale-deploy/headplane/`**
    * Contains files specific to the Headplane UI service.
* **`headscale-deploy/headplane/config.yaml`**
    * Main configuration file for Headplane (server settings, Headscale connection, OIDC).
* **`headscale-deploy/headplane/secrets/`**
    * Directory for sensitive Headplane credentials.
* **`headscale-deploy/headplane/secrets/oidc_client_secret`**
    * Contains the OIDC client secret (e.g., from Google).
    * **Sensitive** - Recommend `chmod 600`.
* **`headscale-deploy/headplane/users/`**
    * Directory for Headplane user data.
* **`headscale-deploy/headplane/users/users.json`**
    * Defines Headplane users.
    * May contain sensitive info - Recommend `chmod 600` or `640`.
    * Consider if it should be committed to Git.
* **`headscale-deploy/headscale/`**
    * Contains files specific to the Headscale coordination server service.
* **`headscale-deploy/headscale/config/`**
    * Directory for Headscale configuration.
* **`headscale-deploy/headscale/config/config.yaml`**
    * The main Headscale configuration file (server URL, ports, DB path, etc.).
* **`headscale-deploy/headscale/data/`**
    * Persistent storage for Headscale (e.g., the SQLite database).
    * Should NOT be committed to Git.
* **`headscale-deploy/traefik/`**
    * Contains files specific to the Traefik reverse proxy service.
* **`headscale-deploy/traefik/auth/`**
    * Optional: Directory for authentication configurations (e.g., Basic Auth).
* **`headscale-deploy/traefik/auth/users.htpasswd`**
    * Basic Authentication user file.
    * **Sensitive** - Recommend `chmod 600` or `640`.
    * Should NOT be committed to Git.
* **`headscale-deploy/traefik/certificates/`**
    * Stores ACME (Let's Encrypt) certificates obtained by Traefik.
* **`headscale-deploy/traefik/certificates/acme.json`**
    * The file where Traefik stores Let's Encrypt certificates & private keys.
    * **CRITICAL** - MUST use `chmod 600`.
    * Should NOT be committed to Git.
* **`headscale-deploy/traefik/logs/`**
    * Stores logs generated by Traefik.
* **`headscale-deploy/traefik/logs/traefik.log`**
    * Traefik operational logs or access logs (depending on config).
    * Should likely NOT be committed to Git.
* **`headscale-deploy/traefik/tls.yml`**
    * Traefik dynamic configuration file, often used for custom TLS options, cipher suites, etc.

## Environment Variables (.env)

Create a file named `.env` in the root of your `headscale-deploy` directory. This will store your domain names and email.

```
# .env
HS_URL=heads.yourdomain.com
HUI_URL=hsadmin.yourdomain.com
LE_EMAIL=your-email@example.com
```

**-> Remember to replace the placeholder values with your actual domain names and email!**

## Configuration Files

###   1.  Headscale (`headscale/config/config.yaml`)

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
    grpc_listen_addr: 127.0.0.0:50443
    grpc_allow_insecure: false # Use true ONLY if needed for specific tooling, usually false

    # Database configuration
    db_type: sqlite
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

###   2.  Headplane (`headplane/config.yaml`)

    Create this file to configure the Headplane UI.

    ```yaml
    # headplane/config.yaml

    server:
        host: "0.0.0.0"
        port: 3000
        cookie_secret: "REPLACE_THIS_WITH_A_32_CHAR_SECURE_SECRET" # Change this!
        cookie_secure: true

    headscale:
        url: "[https://heads.alisufyan.cloud](https://heads.alisufyan.cloud)"  # "http://headscale:8080"
        config_path: "/etc/headscale/config.yaml"
        config_strict: true

    # Integration configurations
    integration:
        docker:
            enabled: true
            container_name: "headscale"
            socket: "unix:///var/run/docker.sock"
        kubernetes:
            enabled: false
            validate_manifest: true
            pod_name: "headscale"
        proc:
            enabled: false

    # OIDC Configuration
    oidc:
        issuer: "[https://accounts.google.com](https://accounts.google.com)"
        client_id: "ID_HERE"
        client_secret_path: "/etc/headplane/secrets/oidc_client_secret"
        disable_api_key_login: false
        token_endpoint_auth_method: "client_secret_post"
        headscale_api_key: "KEY_HERE"
        redirect_uri: "https://${HS_URL}/admin/oidc/callback"
        user_storage_file: "/var/lib/headplane/users.json"

    # Optional: Enable PKCE for added security (recommended if your clients support it)
    # pkce:
    #    enabled: true
    #    method: S256
    ```

    **-> Remember to generate and set a strong `cookie_secret`!**

###   3.  Docker Compose (`docker-compose.yaml`)

    This file in the root of your `headscale-deploy` directory defines all the services and their interactions. It uses environment variables for domain names and email and includes a `secureHeaders` middleware and TLS options.

    ```yaml
    version: "3.8" # Or a compatible version
    services:

        headscale:
            image: headscale/headscale:0.25.1 # Specifies the version of Headscale to use
            pull_policy: always
            container_name: headscale
            restart: unless-stopped
            command: serve
            volumes:
                - ./headscale/config:/etc/headscale # Configuration files for Headscale
                - ./headscale/data:/var/lib/headscale # Data storage for Headscale
            labels:
                - traefik.enable=true
                - traefik.http.routers.headscale-rtr.rule=Host(`${HS_URL}`) # URL for accessing Headscale - add in .env
                - traefik.http.routers.headscale-rtr.priority=90
                - traefik.http.routers.headscale-rtr.entrypoints=websecure
                - traefik.http.routers.headscale-rtr.tls.certresolver=myresolver
                - traefik.http.services.headscale-svc.loadbalancer.server.port=8080 # Port for Headscale service
                - traefik.http.routers.headscale-rtr.middlewares=corsHeader@docker,secureHeaders@docker,cspHeader@docker # Apply CSP

        headplane:
            image: ghcr.io/tale/headplane:0.5.7 # Specifies the version of Headplane
            pull_policy: always
            container_name: headplane
            restart: unless-stopped
            deploy:
                resources:
                    limits:
                        cpus: '0.50'
                        memory: 512M
                    reservations:
                        cpus: '0.25'
                        memory: 128M
            volumes:
                - ./headplane/config.yaml:/etc/headplane/config.yaml # Configuration for Headplane
                - ./headscale/config:/etc/headscale # Shared Headscale configuration
                - /var/run/docker.sock:/var/run/docker.sock:ro # Docker socket for container management
                - ./headplane/users/users.json:/var/lib/headplane/users.json # Persist user storage file
                - ./headplane/secrets/oidc_client_secret:/etc/headplane/secrets/oidc_client_secret:ro # OICD Secret via File Mounts
            depends_on:
                - headscale # Ensure Headscale starts before Headplane
            labels:
                - traefik.enable=true
                # Router Definition
                - traefik.http.routers.headplane-rtr.rule=Host(`${HS_URL}`) && PathPrefix(`/admin`)
                - traefik.http.routers.headplane-rtr.priority=100
                - traefik.http.routers.headplane-rtr.entrypoints=websecure
                - traefik.http.routers.headplane-rtr.tls.certresolver=myresolver
                - traefik.http.services.headplane-svc.loadbalancer.server.port=3000 # headplane port
                # ---- Middleware for redirect ----
                - traefik.http.middlewares.headplane-addslash.redirectregex.regex=^https?://([^/]+)/admin$$
                - traefik.http.middlewares.headplane-addslash.redirectregex.replacement=https://$${1}/admin/
                - traefik.http.middlewares.headplane-addslash.redirectregex.permanent=true
                - traefik.http.routers.headplane-rtr.middlewares=headplane-addslash@docker,corsHeader@docker,secureHeaders@docker,cspHeader@docker

        headscale-admin:
            image: goodieshq/headscale-admin:0.25.5
            container_name: headscale-admin
            restart: unless-stopped
            pull_policy: always # Or your preferred policy
            labels:
                - traefik.enable=true
                - traefik.http.routers.headscale-admin-extra-rtr.rule=Host(`${HUI_URL}`)
                - traefik.http.routers.headscale-admin-extra-rtr.entrypoints=websecure
                - traefik.http.routers.headscale-admin-extra-rtr.tls.certresolver=myresolver
                - traefik.http.services.headscale-admin-extra-svc.loadbalancer.server.port=80
                - traefik.http.routers.headscale-admin-extra-rtr.middlewares=corsHeader@docker

        traefik:
            image: traefik:v3.3.5 # Specifies the version of Traefik to use
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
                - --entrypoints.web.address=:80 # HTTP entry point
                - --entrypoints.websecure.address=:443 # HTTPS entry point
                - --certificatesresolvers.myresolver.acme.tlschallenge=true
                - --certificatesresolvers.myresolver.acme.email=${LE_EMAIL} # add in .env
                - --certificatesresolvers.myresolver.acme.storage=/certificates/acme.json
                - --global.sendAnonymousUsage=false
                - --entrypoints.websecure.http.tls.options=securetls@file # for TLS
            ports:
                - 80:80 # Maps host port 80 to container port 80 for HTTP
                - 443:443 # Maps host port 443 to container port 443 for HTTPS
            volumes:
                - /var/run/docker.sock:/var/run/docker.sock:ro
                - ./traefik/certificates:/certificates
                - ./traefik/logs/traefik.log:/var/log/traefik.log
                - ./traefik/tls.yml:/tls.yml # Custom TLS
                - ./traefik/auth:/auth
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
            deploy:
                resources:
                    limits:
                        memory: 512M
                        cpus: '0.50'
                    reservations:
                        memory: 128M
                        cpus: '0.25'
            labels:
                # Basic Auth Middleware
                - traefik.http.middlewares.auth.basicauth.usersfile=/auth/users.htpasswd

                # CORS middleware for API calls
                - traefik.http.middlewares.corsHeader.headers.accesscontrolallowmethods=GET,OPTIONS,PUT
                - traefik.http.middlewares.corsHeader.headers.accesscontrolallowheaders=Authorization,*
                - traefik.http.middlewares.corsHeader.headers.accesscontrolalloworiginlist=https://${HS_URL},https://${HUI_URL}
                - traefik.http.middlewares.corsHeader.headers.accesscontrolmaxage=43200
                - traefik.http.middlewares.corsHeader.headers.addvaryheader=true

                # Redirect HS root path (/) to /admin (Now served by headplane)
                - traefik.http.middlewares.redirect-hs-root-to-admin.redirectregex.regex=^https?://([^/]+)/?$$
                - traefik.http.middlewares.redirect-hs-root-to-admin.redirectregex.replacement=https://$${1}/admin
                - traefik.http.middlewares.redirect-hs-root-to-admin.redirectregex.permanent=true
                - traefik.http.routers.hs-root-redirect.rule=Host(`${HS_URL}`) && Path(`/`)
                - traefik.http.routers.hs-root-redirect.priority=95 # Higher than headscale (90), lower than headplane (100)
                - traefik.http.routers.hs-root-redirect.entrypoints=websecure
                - traefik.http.routers.hs-root-redirect.tls.certresolver=myresolver
                - traefik.http.routers.hs-root-redirect.middlewares=redirect-hs-root-to-admin@docker,secureHeaders@docker,cspHeader@docker # Apply CSP
                - traefik.http.routers.hs-root-redirect.service=noop@internal

                # ---- REDIRECT FOR HUI - Headsscale-admin ----
                - traefik.http.middlewares.redirect-hui-root-to-admin.redirectregex.regex=^https?://${HUI_URL}/?$$
                - traefik.http.middlewares.redirect-hui-root-to-admin.redirectregex.replacement=https://${HUI_URL}/admin
                - traefik.http.middlewares.redirect-hui-root-to-admin.redirectregex.permanent=true
                - traefik.http.routers.hui-root-redirect.rule=Host(`${HUI_URL}`) && Path(`/`)
                - traefik.http.routers.hui-root-redirect.entrypoints=websecure
                - traefik.http.routers.hui-root-redirect.tls.certresolver=myresolver
                - traefik.http.routers.hui-root-redirect.service=noop@internal
                - traefik.http.routers.hui-root-redirect.middlewares=redirect-hui-root-to-admin@docker,secureHeaders@docker # add secureHeaders@docker etc

                # HSTS Security Headers
                - traefik.http.middlewares.secureHeaders.headers.stsSeconds=31536000 # 1 year
                - traefik.http.middlewares.secureHeaders.headers.stsIncludeSubdomains=true
                - traefik.http.middlewares.secureHeaders.headers.stsPreload=true
                - traefik.http.middlewares.secureHeaders.headers.forceSTSHeader=true

                # Global Redirect HTTP to HTTPS
                - traefik.http.routers.http-catchall.rule=hostregexp(`{host:.+}`)
                - traefik.http.routers.http-catchall.entrypoints=web
                - traefik.http.routers.http-catchall.middlewares=redirect-to-https@docker
                - traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https
                - traefik.http.middlewares.redirect-to-https.redirectscheme.permanent=true

                # Enforce Secure Cookies & Enhanced Security
                - traefik.http.middlewares.secureHeaders.headers.browserXssFilter=true
                - traefik.http.middlewares.secureHeaders.headers.contentTypeNosniff=true
                - traefik.http.middlewares.secureHeaders.headers.referrerPolicy=same-origin
                - traefik.http.middlewares.secureHeaders.headers.customrequestheaders.X-Forwarded-Proto=https
                - traefik.http.middlewares.secureHeaders.headers.customresponseheaders.Strict-Transport-Security=max-age=31536000; includeSubDomains; preload
                - traefik.http.middlewares.secureHeaders.headers.frameDeny=true # Prevent Clickjacking
                - traefik.http.middlewares.secureHeaders.headers.permissionsPolicy=geolocation=(), microphone=(), camera=() # Restrict Browser Features

                # Content Security Policy (CSP)
                - traefik.http.middlewares.cspHeader.headers.customresponseheaders.Content-Security-Policy="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"
```

Can you update the README with this?
