# Private Docker Registry Setup Documentation

## Table of Contents
1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Directory Structure](#directory-structure)
4. [Services & Components](#services--components)
5. [Configuration Files](#configuration-files)
6. [Automation Scripts](#automation-scripts)
7. [Security & Credentials](#security--credentials)
8. [Monitoring & Observability](#monitoring--observability)
9. [Backup & Recovery](#backup--recovery)
10. [Maintenance Procedures](#maintenance-procedures)
11. [Troubleshooting](#troubleshooting)
12. [Disaster Recovery](#disaster-recovery)
13. [References & Resources](#references--resources)

---

## Overview

This documentation covers a comprehensive private Docker registry setup running on a Debian 13 VPS. The system provides automated image synchronization from multiple public registries (Docker Hub, GHCR, LSCR, GCR, Quay), complete monitoring stack, security features, and robust operational procedures.

### Key Features
- **Private Docker Registry** with Redis caching
- **Automated Image Synchronization** via regsync
- **Web UI** for registry management
- **Complete Monitoring Stack** (Prometheus + Grafana + cAdvisor)
- **Security Layer** with CrowdSec intrusion detection
- **Automated Backups** to Hetzner Storage Box
- **Multi-channel Notifications** (ntfy + Gotify)
- **Comprehensive Automation** scripts for all operations

### System Requirements
- **OS**: Debian 13
- **Docker**: Latest version with Compose plugin
- **Domain**: `registry.my_domain.tld` (with proper DNS setup)
- **SSL**: Automatic via Caddy
- **Storage**: External backup to Hetzner Storage Box

---

## Architecture

### Network Architecture
```
Internet → Caddy (Port 443/8080) → Internal Services
├── Docker Registry (Port 5000)
├── Registry UI
├── Prometheus (Port 9090)
├── Grafana (Port 3000)
├── CrowdSec (Port 8080)
└── Portainer
```

### Data Flow
1. **External requests** → Caddy reverse proxy
2. **Image pulls/pushes** → Docker Registry → Redis cache
3. **Monitoring data** → Prometheus → Grafana dashboards
4. **Security events** → CrowdSec → Log analysis
5. **Registry events** → Webhook receiver → Notifications

---

## Directory Structure

```
/home/user/registry/
├── caddy/                      # Caddy reverse proxy
│   ├── Caddyfile              # Caddy configuration
│   ├── config/                # Caddy config storage
│   ├── data/                  # Caddy data (certificates)
│   └── logs/                  # Access logs
├── crowdsec/                   # Security monitoring
│   ├── config/                # CrowdSec configuration
│   └── data/                  # CrowdSec data
├── docker-compose.yml         # Main orchestration file
├── docker-registry/           # Registry core
│   ├── config.yml             # Registry configuration
│   ├── config.yml.bak         # Configuration backup
│   └── data/                  # Registry image storage
├── grafana/                   # Monitoring dashboards
│   ├── grafana-config/        # Configuration files
│   ├── grafana-data/          # Dashboard data
│   ├── grafana-logs/          # Application logs
│   └── grafana-provisioning/ # Auto-provisioning configs
├── logs/                      # Centralized logging
│   ├── cron-job_logs/         # Scheduled job logs
│   └── log_archive/           # Rotated log archive
├── portainer_data/            # Container management UI
├── prometheus/                # Metrics collection
│   ├── prometheus_data/       # Time-series data
│   └── prometheus.yml         # Prometheus configuration
├── redis/                     # Registry caching
│   ├── config/                # Redis configuration
│   └── data/                  # Cache data
├── secrets/                   # Credential storage
│   ├── ghcr_token             # GitHub Container Registry
│   ├── ghcr_user
│   ├── gotify_token           # Gotify notifications
│   ├── gotify_url_secret
│   ├── hub_token              # Docker Hub
│   ├── hub_user
│   ├── ntfy_token             # ntfy notifications
│   ├── oauth2_cookie_secret   # OAuth2 authentication
│   ├── oidc_client_id         # OIDC configuration
│   ├── oidc_client_secret
│   ├── private_registry_identifier
│   ├── registry_host          # Registry hostname
│   ├── registry_pass          # Registry credentials
│   └── registry_user
├── check_changes.sh           # Registry change detection
├── check_sync.sh             # Regsync automation
├── manage_regsync.sh         # Interactive regsync management
├── regbot.yml                # Regbot configuration
├── regsync.yml               # Image synchronization config
├── run_backup.sh             # Backup automation
└── run_gc.sh                 # Garbage collection
```

---

## Services & Components

### Core Services (docker-compose.yml)

#### Registry Service
- **Image**: `registry:3`
- **Purpose**: Core Docker registry following [official deployment guidelines](https://distribution.github.io/distribution/about/deploying/)
- **Resources**: 1.5 CPU, 2GB RAM
- **Storage**: Filesystem backend with Redis caching
- **Port**: 5000 (internal)
- **Health Check**: Uses `/v2/` endpoint as [recommended](https://github.com/distribution/distribution/issues/629)

#### Caddy (Reverse Proxy)
- **Image**: `ghcr.io/buildplan/cs-caddy:latest`
- **Purpose**: TLS termination and reverse proxy
- **Features**: Automatic HTTPS, access logging
- **Ports**: 8080, 443
- **Security**: Follows [registry TLS best practices](https://distribution.github.io/distribution/about/deploying/#get-a-certificate)

#### Redis (Cache Layer)
- **Image**: `redis:alpine`
- **Purpose**: Registry blob caching for improved performance
- **Resources**: 0.25 CPU, 256MB RAM
- **Configuration**: Custom redis.conf for registry optimization

#### Registry UI
- **Image**: `joxit/docker-registry-ui:main`
- **Purpose**: Web interface for registry browsing
- **Features**: Dark theme, image deletion capability
- **Dependencies**: Registry service

#### Regsync (Synchronization)
- **Image**: `ghcr.io/regclient/regsync:latest`
- **Purpose**: Automated image synchronization from multiple registries
- **Mode**: Server mode with scheduled syncing
- **Resources**: 0.5 CPU, 512MB RAM
- **Documentation**: [Official regsync guide](https://regclient.org/usage/regsync/)

#### Regbot (Registry Management)
- **Image**: `ghcr.io/regclient/regbot:latest`
- **Purpose**: Registry automation and management
- **Resources**: 0.25 CPU, 256MB RAM

### Monitoring Stack

#### Prometheus
- **Purpose**: Metrics collection and storage
- **Resources**: 0.5 CPU, 512MB RAM
- **Storage**: Local time-series database
- **Port**: 9090
- **Integration**: Registry metrics endpoint enabled

#### Grafana
- **Purpose**: Metrics visualization and dashboards
- **Resources**: 0.5 CPU, 512MB RAM
- **Authentication**: Admin credentials via environment
- **Port**: 3000

#### cAdvisor
- **Purpose**: Container metrics collection
- **Privileges**: Requires privileged mode for system metrics
- **Resources**: 0.25 CPU, 512MB RAM
- **Port**: 8080

### Security & Management

#### CrowdSec
- **Purpose**: Intrusion detection and prevention
- **Resources**: 0.5 CPU, 1GB RAM
- **Integration**: Caddy log analysis
- **Health Check**: Built-in status monitoring

#### Portainer
- **Purpose**: Docker container management UI
- **Resources**: 0.25 CPU, 256MB RAM
- **Access**: Docker socket mounted

#### Registry Webhook Receiver
- **Purpose**: Registry event notifications
- **Integration**: ntfy notifications
- **Resources**: 0.25 CPU, 128MB RAM

---

## Configuration Files

### Registry Configuration (docker-registry/config.yml)

Based on the [official configuration reference](https://distribution.github.io/distribution/about/configuration/), the registry is configured with:

```yaml
version: 0.1
log:
  level: info
  formatter: text
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true                    # Enables image deletion
cache:
  blobdescriptor: redis             # Redis caching for performance
http:
  addr: :5000
  secret: [REDACTED]                # HTTP secret for upload coordination
debug:
  addr: :5001
  prometheus:
    enabled: true                   # Metrics endpoint
    path: /metrics
notifications:
  events:
    includereferences: true
  endpoints:
    - name: ntfy
      disabled: false
      url: https://ntfy.my_domain.tld/registry-events
      headers:
        Authorization: Bearer [TOKEN]
        Title: Docker Registry Event
        Tags: docker
      timeout: 3s
      threshold: 5
      backoff: 5s
health:
  storagedriver:
    enabled: true                   # Storage health checks
    interval: 10s
    threshold: 3
redis:
  addrs: ["redis:6379"]
  db: 0
  # Connection pool settings optimized for registry caching
```

**Key Security Features**:
- TLS termination handled by Caddy proxy
- Basic authentication for push operations
- Redis caching for improved performance
- Webhook notifications for registry events
- Health checks for storage driver

### Regsync Configuration (regsync.yml)

Following [regsync best practices](https://regclient.org/usage/regsync/), the configuration includes:

- **Version**: 1
- **Sync Interval**: 12 hours (prevents upstream rate limiting)
- **Parallelism**: 1 (sequential processing for stability)
- **Registries**: 120+ image synchronizations
- **Source Registries**: 
  - Docker Hub (with authentication)
  - GitHub Container Registry (GHCR)
  - LinuxServer.io Container Registry (LSCR)
  - Google Container Registry (GCR)
  - Quay.io
  - Codeberg.org
- **Authentication**: File-based credentials for authenticated registries
- **Tag Filtering**: Smart regex patterns for version control

### Log Rotation (/etc/logrotate.d/private-registry-logs)
```
/home/user/registry/logs/*.log /home/user/registry/logs/cron-job_logs/*.log {
    daily
    rotate 3
    compress
    delaycompress
    missingok
    notifempty
    create 0644 user user
    su user user
    dateext
    dateformat -%Y%m%d
    olddir /home/user/registry/logs/log_archive
}
```

---

## Automation Scripts

### check_sync.sh - Regsync Automation
**Purpose**: Automated image synchronization with state management  
**Source**: [GitHub Repository](https://github.com/buildplan/docker/blob/main/private-registry-stack/check_and_sync.sh)

**Key Features**:
- State-aware execution (6-hour minimum interval)
- Comprehensive error handling with `set -e` and `set -o pipefail`
- ntfy notifications for all outcomes
- Detailed logging with color-coded output
- Robust image summary parsing (improved version available)

**Execution Flow**:
1. Check minimum interval requirement via state file
2. Run regsync check command to detect needed updates
3. If updates needed, execute sync operation
4. Send notifications based on results
5. Update state file with timestamp

**Usage**: 
```bash
./check_sync.sh
```

**Cron Integration**: 
```bash
# Add to crontab for automated execution
0 */6 * * * /home/user/registry/check_sync.sh
```

### run_backup.sh - Backup Automation
**Purpose**: Consistent backup to Hetzner Storage Box  
**Source**: [GitHub Repository](https://github.com/buildplan/docker/blob/main/private-registry-stack/backup_home_to_hetzner.sh)

**Key Features**:
- Service coordination (stops registry during backup for consistency)
- SSH key authentication to Hetzner Storage Box
- Gotify notifications for backup status
- Graceful service recovery regardless of backup outcome
- Complete project directory synchronization

**Backup Process**:
1. Stop registry service for data consistency
2. rsync entire project directory to Hetzner Storage Box
3. Restart registry service
4. Send success/failure notifications with details

**Usage**:
```bash
# Manual execution (requires sudo for stopping services)
sudo ./run_backup.sh

# Scheduled execution via cron
0 2 * * * /home/user/registry/run_backup.sh
```

### run_gc.sh - Garbage Collection
**Purpose**: Registry cleanup and space management

**Process**:
1. Stop registry service to prevent writes during GC
2. Run garbage collection with `--delete-untagged` flag
3. Restart registry service
4. Report results via ntfy with deletion statistics

**Usage**:
```bash
./run_gc.sh
```

### check_changes.sh - Change Detection
**Purpose**: Monitor registry content changes

**Features**:
- Uses regctl for repository listing
- Diff-based change detection between runs
- Formatted notifications with change details
- State file management for persistent tracking

### manage_regsync.sh - Interactive Management
**Purpose**: User-friendly regsync configuration management

**Features**:
- Interactive menu system with color-coded output
- Add/Edit/Delete sync entries with validation
- Search functionality across sync entries
- Dry-run mode for testing changes
- Automatic backups before configuration changes
- Table-formatted display with proper text wrapping

**Usage**:
```bash
# Interactive mode
./manage_regsync.sh

# Dry-run mode (preview changes without applying)
./manage_regsync.sh --dry-run
```

---

## Security & Credentials

### Credential Management
All sensitive credentials are stored in the `secrets/` directory with proper file permissions (600). The system uses file-based credential loading to avoid exposing secrets in configuration files or environment variables, following [Docker security best practices](https://distribution.github.io/distribution/about/deploying/#access-restrictions).

### Security Layers
1. **TLS Encryption**: Automatic HTTPS via Caddy with Let's Encrypt
2. **Intrusion Detection**: CrowdSec monitoring and analysis
3. **Access Control**: Registry authentication for push operations
4. **Network Isolation**: Docker bridge network segmentation
5. **Resource Limits**: Container resource constraints to prevent resource exhaustion
6. **Credential Separation**: External secret file management

### Authentication Flow
- **Pull Operations**: Anonymous access allowed for efficiency
- **Push Operations**: Authenticated via registry credentials
- **UI Access**: Protected by reverse proxy configuration
- **Monitoring Access**: Internal network only

**Security Configuration Compliance**:
- Follows [official registry authentication guidelines](https://distribution.github.io/distribution/spec/auth/token/)
- Implements [production deployment security](https://distribution.github.io/distribution/about/deploying/#access-restrictions)
- Uses bcrypt password hashing for htpasswd authentication

---

## Monitoring & Observability

### Metrics Collection
- **Registry Metrics**: Native Prometheus endpoint (`/metrics`)
- **Container Metrics**: cAdvisor collection for all services
- **System Metrics**: Host-level monitoring via cAdvisor
- **Application Metrics**: Service-specific exporters

### Notification Channels
1. **ntfy**: Primary notification system
   - Registry events (push/pull/delete)
   - Sync status updates
   - System alerts and failures
   
2. **Gotify**: Secondary notification system
   - Backup status reports
   - Configuration changes
   - Manual operations

### Dashboard Access
- **Grafana**: `https://registry.my_domain.tld/grafana`
- **Prometheus**: `https://registry.my_domain.tld/prometheus`
- **Registry UI**: `https://registry.my_domain.tld`
- **Portainer**: Internal access for container management

---

## Backup & Recovery

### Backup Strategy
- **Frequency**: Daily automated backups at 2 AM
- **Destination**: Hetzner Storage Box (reliable cloud storage)
- **Method**: rsync with SSH key authentication
- **Scope**: Complete `/home/user/registry` directory
- **Consistency**: Registry service stopped during backup to ensure data integrity

### Backup Components
- Registry image data and metadata
- Configuration files and secrets
- Monitoring data and dashboards
- Log files and archives
- Application state and databases

### Recovery Procedures
1. **Complete System Recovery**:
   ```bash
   # Restore from Hetzner backup
   rsync -avz --delete -e "ssh -p 23 -i ~/.ssh/id_hetzner_backup" \
     u457300-sub3@u457300.your-storagebox.de:home/private-registry/ \
     /home/user/registry/
   
   # Restore permissions
   chown -R user:user /home/user/registry
   chmod -R 755 /home/user/registry
   chmod 600 /home/user/registry/secrets/*
   
   # Start services
   cd /home/user/registry
   docker compose up -d
   ```

2. **Selective Recovery**:
   - Individual service data restoration
   - Configuration rollback using .bak files
   - Secret file recovery from backup

---

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily
- Monitor notification channels for alerts
- Review backup success notifications
- Check system resource usage via Grafana

#### Weekly
- Review Grafana dashboards for performance trends
- Check log rotation and archive sizes
- Verify sync operations are functioning correctly
- Update synchronized image list if needed

#### Monthly
- Run manual garbage collection if needed
- Review and update synchronized images
- Security update check for all containers
- Backup verification test
- Review and rotate credentials

### Image Management
1. **Adding New Images**:
   ```bash
   ./manage_regsync.sh
   # Select: Add Sync Entry
   # Follow interactive prompts
   ```

2. **Updating Sync Configuration**:
   ```bash
   # Edit existing entries
   ./manage_regsync.sh
   # Select: Edit Sync Entry
   ```

3. **Removing Unused Images**:
   ```bash
   # Manual cleanup via UI or API
   # Followed by garbage collection
   ./run_gc.sh
   ```

### System Updates
1. **Container Updates**:
   ```bash
   cd /home/user/registry
   docker compose pull
   docker compose up -d
   ```

2. **Configuration Updates**:
   - Always backup before changes using the built-in backup functions
   - Test in dry-run mode where possible
   - Verify services after updates

---

## Troubleshooting

### Common Issues

#### Registry Not Accessible
**Symptoms**: Cannot access registry web UI or API
**Troubleshooting Steps**:
1. Check Caddy status and logs:
   ```bash
   docker compose logs caddy
   ```
2. Verify DNS configuration and SSL certificate status
3. Check firewall rules and port accessibility
4. Verify registry service health:
   ```bash
   curl -I https://registry.my_domain.tld/v2/
   ```

#### Sync Failures
**Symptoms**: Images not updating, sync errors in logs
**Troubleshooting Steps**:
1. Check regsync logs:
   ```bash
   docker compose logs regsync
   ```
2. Verify credentials in secrets directory
3. Test network connectivity to source registries
4. Check disk space availability
5. Review rate limiting issues

#### Backup Failures
**Symptoms**: Backup notifications showing failures
**Troubleshooting Steps**:
1. Verify SSH key permissions and accessibility
2. Check Hetzner Storage Box connectivity:
   ```bash
   ssh -p 23 -i ~/.ssh/id_hetzner_backup u457300-sub3@u457300.your-storagebox.de
   ```
3. Verify rsync command parameters
4. Check disk space on both source and destination

#### Performance Issues
**Symptoms**: Slow image pulls, high resource usage
**Troubleshooting Steps**:
1. Monitor resource usage via Grafana dashboards
2. Check Redis cache hit rates and performance
3. Verify disk I/O performance
4. Review container resource limits
5. Check for network bottlenecks

### Log Locations
- **Application Logs**: `/home/user/registry/logs/`
- **Container Logs**: `docker compose logs [service]`
- **System Logs**: `/var/log/` (via CrowdSec integration)
- **Archived Logs**: `/home/user/registry/logs/log_archive/`

### Diagnostic Commands
```bash
# Service status overview
docker compose ps

# Resource usage monitoring
docker stats

# Registry API health check
curl -s https://registry.my_domain.tld/v2/_catalog

# Regsync version and status
docker compose exec regsync regsync -c /config/regsync.yml version

# Check disk usage
df -h /home/user/registry/

# Network connectivity test
docker compose exec regsync ping docker.io

# Redis cache status
docker compose exec redis redis-cli info
```

---

## Disaster Recovery

### Complete System Failure
1. **Prepare New System**:
   - Install Docker and Docker Compose
   - Configure user account and SSH keys
   - Set up network and firewall rules

2. **Restore Data**:
   ```bash
   # Create directory structure
   mkdir -p /home/user/registry
   
   # Restore from backup
   rsync -avz -e "ssh -p 23 -i ~/.ssh/id_hetzner_backup" \
     u457300-sub3@u457300.your-storagebox.de:home/private-registry/ \
     /home/user/registry/
   ```

3. **Restore Services**:
   ```bash
   cd /home/user/registry
   # Pull latest images
   docker compose pull
   # Start all services
   docker compose up -d
   ```

4. **Verification**:
   - Test registry accessibility
   - Verify all services are running healthy
   - Check monitoring dashboards
   - Test image pull/push operations
   - Verify backup and sync operations

### Partial Recovery Scenarios
- **Configuration corruption**: Restore from .bak files or backup
- **Data loss**: Selective restore from Hetzner backup
- **Service failure**: Container restart or image rebuild
- **Network issues**: DNS/firewall reconfiguration
- **Certificate issues**: Caddy certificate regeneration

### Recovery Time Objectives
- **RTO (Recovery Time Objective)**: 4 hours for complete system recovery
- **RPO (Recovery Point Objective)**: 24 hours (daily backup frequency)
- **Service Availability**: 99.5% target uptime
- **Data Retention**: 3 days of rotated logs, indefinite backup retention

---

## References & Resources

### Official Documentation
- **Docker Registry Deployment Guide**: [https://distribution.github.io/distribution/about/deploying/](https://distribution.github.io/distribution/about/deploying/)
- **Registry Configuration Reference**: [https://distribution.github.io/distribution/about/configuration/](https://distribution.github.io/distribution/about/configuration/)
- **Registry Authentication**: [https://distribution.github.io/distribution/spec/auth/token/](https://distribution.github.io/distribution/spec/auth/token/)
- **Regsync Documentation**: [https://regclient.org/usage/regsync/](https://regclient.org/usage/regsync/)
- **Regclient FAQ**: [https://regclient.org/usage/faq/](https://regclient.org/usage/faq/)

### Security Resources
- **Registry Security Best Practices**: [https://distribution.github.io/distribution/about/deploying/#access-restrictions](https://distribution.github.io/distribution/about/deploying/#access-restrictions)
- **Testing Insecure Registries**: [https://distribution.github.io/distribution/about/insecure/](https://distribution.github.io/distribution/about/insecure/)
- **Container Registry Best Practices**: [https://learn.microsoft.com/en-us/azure/container-registry/container-registry-best-practices](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-best-practices)

### Monitoring & Observability
- **Docker Monitoring with Prometheus**: [https://last9.io/blog/docker-monitoring-with-prometheus-a-step-by-step-guide/](https://last9.io/blog/docker-monitoring-with-prometheus-a-step-by-Step-guide/)
- **Grafana Docker Compose Setup**: [https://grafana.com/docs/grafana-cloud/send-data/metrics/metrics-prometheus/prometheus-config-examples/docker-compose-linux/](https://grafana.com/docs/grafana-cloud/send-data/metrics/metrics-prometheus/prometheus-config-examples/docker-compose-linux/)

### Proxy and Load Balancing
- **Nginx Authentication Proxy**: [https://distribution.github.io/distribution/recipes/nginx/](https://distribution.github.io/distribution/recipes/nginx/)
- **Registry with systemd**: [https://distribution.github.io/distribution/recipes/systemd/](https://distribution.github.io/distribution/recipes/systemd/)

### Community Resources
- **Registry GitHub Issues**: [https://github.com/distribution/distribution/issues](https://github.com/distribution/distribution/issues)
- **Regclient Package Documentation**: [https://pkg.go.dev/github.com/regclient/regclient](https://pkg.go.dev/github.com/regclient/regclient)
- **Chainguard Regsync Image**: [https://images.chainguard.dev/directory/image/regclient-regsync/overview](https://images.chainguard.dev/directory/image/regclient-regsync/overview)

### Source Code
- **Main Scripts Repository**: [https://github.com/buildplan/docker/tree/main/private-registry-stack](https://github.com/buildplan/docker/tree/main/private-registry-stack)
- **Sync Automation Script**: [https://github.com/buildplan/docker/blob/main/private-registry-stack/check_and_sync.sh](https://github.com/buildplan/docker/blob/main/private-registry-stack/check_and_sync.sh)
- **Backup Script**: [https://github.com/buildplan/docker/blob/main/private-registry-stack/backup_home_to_hetzner.sh](https://github.com/buildplan/docker/blob/main/private-registry-stack/backup_home_to_hetzner.sh)

### Troubleshooting Resources
- **Registry Health Checks**: [https://github.com/distribution/distribution/issues/629](https://github.com/distribution/distribution/issues/629)
- **Token Authentication Issues**: [https://github.com/distribution/distribution/issues/3290](https://github.com/distribution/distribution/issues/3290)
- **JWKS Configuration**: [https://github.com/distribution/distribution/issues/4470](https://github.com/distribution/distribution/issues/4470)

---

## Conclusion

This private Docker registry setup represents a production-ready, enterprise-grade solution with comprehensive automation, monitoring, security, and operational procedures. The system is designed for reliability, maintainability, and scalability while providing complete visibility into all operations through extensive logging and notification systems.

The implementation follows official Docker registry deployment guidelines and incorporates industry best practices for container registry management. The comprehensive automation ensures minimal manual intervention while maintaining high availability and data integrity.

Regular maintenance following the procedures outlined in this documentation will ensure optimal performance and reliability of the registry infrastructure. The extensive monitoring and notification systems provide early warning of potential issues, enabling proactive maintenance and rapid issue resolution.

---

*Documentation last updated: August 22, 2025*  
*Based on: Docker Registry v3, Debian 13, Docker Compose*
