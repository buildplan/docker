### This image can be used alongside registry:3 (https://hub.docker.com/_/registry) to configure notifications for your private docker registry.

#### Docker compose example:

```
networks:
  registry-net:
    driver: bridge

services:
  # --- registry ---
  registry:
    image: registry:3.0.0
    container_name: registry_service
    volumes: # create volumes before starting the containers
      - ./docker-registry/data:/var/lib/registry
      - ./docker-registry/config.yml:/etc/distribution/config.yml:ro
    networks:
      - registry-net
    environment:
      OTEL_TRACES_EXPORTER: "none"
      REGISTRY_HTTP_SECRET: ${REGISTRY_HTTP_SECRET} # add in .env
    restart: unless-stopped

  # --- NOTIFICATION APP SERVICE ---
  registry-webhook-receiver:
    image: iamdockin/registry-webhook-receiver:latest
    container_name: registry-webhook-receiver
    restart: unless-stopped
    networks:
      - registry-net
    environment: # add below in .env
      - NTFY_SERVER_URL=${NTFY_SERVER_URL}
      - NTFY_TOPIC=${NTFY_TOPIC}
      - NTFY_ACCESS_TOKEN=${NTFY_ACCESS_TOKEN}
      - NTFY_PRIORITY=${NTFY_PRIORITY:-default}
      - FLASK_ENV=production
```

#### Update your config.yml example below:

```
version: 0.1
log:
  level: info
  formatter: text
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
http:
  addr: :5000
  secret: some-very-long-string-here # same as in .env
notifications:
  endpoints:
    - name: "mycustomntfyreceiver"
      url: "http://registry-webhook-receiver:5001/notify"
      timeout: 5s
      threshold: 3
      backoff: 10s
```

#### Create a .env file example:

```
REGISTRY_HTTP_SECRET=some-very-long-string-here

NTFY_SERVER_URL=https://ntfy.myserver.tld
NTFY_TOPIC=my_private_registry
NTFY_ACCESS_TOKEN=tk_xxxxxxxxxx # access token from ntfy
NTFY_PRIORITY=default
```
