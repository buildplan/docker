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
- **Purpose**: Core Docker registry
- **Resources**: 1.5 CPU, 2GB RAM
- **Storage**: Filesystem backend with Redis caching
- **Port**: 5000 (internal)

#### Caddy (Reverse Proxy)
- **Image**: `ghcr.io/buildplan/cs-caddy:latest`
- **Purpose**: TLS termination and reverse proxy
- **Features**: Automatic HTTPS, access logging
- **Ports**: 8080, 443

#### Redis (Cache Layer)
- **Image**: `redis:alpine`
- **Purpose**: Registry blob caching
- **Resources**: 0.25 CPU, 256MB RAM
- **Configuration**: Custom redis.conf

#### Registry UI
- **Image**: `joxit/docker-registry-ui:main`
- **Purpose**: Web interface for registry browsing
- **Features**: Dark theme, image deletion capability
- **Dependencies**: Registry service

#### Regsync (Synchronization)
- **Image**: `ghcr.io/regclient/regsync:latest`
- **Purpose**: Automated image synchronization
- **Mode**: Server mode with scheduled syncing
- **Resources**: 0.5 CPU, 512MB RAM

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

#### Grafana
- **Purpose**: Metrics visualization and dashboards
- **Resources**: 0.5 CPU, 512MB RAM
- **Authentication**: Admin credentials via environment
- **Port**: 3000

#### cAdvisor
- **Purpose**: Container metrics collection
- **Privileges**: Requires privileged mode
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
```yaml
version: 0.1
log:
  level: info
  formatter: text
storage:
  filesystem:
    rootdirectory: /var/lib/registry
  delete:
    enabled: true
cache:
  blobdescriptor: redis
http:
  addr: :5000
  secret: [REDACTED]
debug:
  addr: :5001
  prometheus:
    enabled: true
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
    enabled: true
    interval: 10s
    threshold: 3
redis:
  addrs: ["redis:6379"]
  db: 0
  # Connection pool settings optimized for registry caching
```

### Regsync Configuration (regsync.yml)
- **Version**: 1
- **Sync Interval**: 12 hours
- **Parallelism**: 1 (sequential processing)
- **Registries**: 120+ image synchronizations
- **Source Registries**: Docker Hub, GHCR, LSCR, GCR, Quay, Codeberg
- **Authentication**: File-based credentials for authenticated registries

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

**Key Features**:
- State-aware execution (6-hour minimum interval)
- Comprehensive error handling
- ntfy notifications for all outcomes
- Detailed logging with color-coded output

**Execution Flow**:
1. Check minimum interval requirement
2. Run regsync check command
3. If updates needed, execute sync
4. Send notifications based on results
5. Update state file

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

**Key Features**:
- Service coordination (stops registry during backup)
- SSH key authentication
- Gotify notifications
- Graceful service recovery

**Backup Process**:
1. Stop registry service for consistency
2. rsync to Hetzner Storage Box
3. Restart registry service
4. Send success/failure notifications

**Usage**:
```bash
# Manual execution (requires sudo)
sudo ./run_backup.sh

# Scheduled execution via cron
0 2 * * * /home/user/registry/run_backup.sh
```

### run_gc.sh - Garbage Collection
**Purpose**: Registry cleanup and space management

**Process**:
1. Stop registry service
2. Run garbage collection with --delete-untagged
3. Restart registry service
4. Report results via ntfy

**Usage**:
```bash
./run_gc.sh
```

### check_changes.sh - Change Detection
**Purpose**: Monitor registry content changes

**Features**:
- Uses regctl for repository listing
- Diff-based change detection
- Formatted notifications with change details
- State file management

### manage_regsync.sh - Interactive Management
**Purpose**: User-friendly regsync configuration management

**Features**:
- Interactive menu system
- Add/Edit/Delete sync entries
- Search functionality
- Dry-run mode for testing
- Automatic backups before changes
- Table-formatted display

**Usage**:
```bash
# Interactive mode
./manage_regsync.sh

# Dry-run mode
./manage_regsync.sh --dry-run
```

---

## Security & Credentials

### Credential Management
All sensitive credentials are stored in the `secrets/` directory with proper file permissions (600). The system uses file-based credential loading to avoid exposing secrets in configuration files or environment variables.

### Security Layers
1. **TLS Encryption**: Automatic HTTPS via Caddy
2. **Intrusion Detection**: CrowdSec monitoring and analysis
3. **Access Control**: Registry authentication for push operations
4. **Network Isolation**: Docker bridge network segmentation
5. **Resource Limits**: Container resource constraints
6. **Credential Separation**: External secret file management

### Authentication Flow
- **Pull Operations**: Anonymous access allowed for efficiency
- **Push Operations**: Authenticated via registry credentials
- **UI Access**: Protected by reverse proxy configuration
- **Monitoring Access**: Internal network only

---

## Monitoring & Observability

### Metrics Collection
- **Registry Metrics**: Native Prometheus endpoint
- **Container Metrics**: cAdvisor collection
- **System Metrics**: Node exporter (if configured)
- **Application Metrics**: Service-specific exporters

### Notification Channels
1. **ntfy**: Primary notification system
   - Registry events
   - Sync status updates
   - System alerts
   
2. **Gotify**: Secondary notification system
   - Backup status
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
- **Frequency**: Daily automated backups
- **Destination**: Hetzner Storage Box
- **Method**: rsync with SSH key authentication
- **Scope**: Complete `/home/user/registry` directory
- **Consistency**: Registry service stopped during backup

### Backup Components
- Registry image data
- Configuration files
- Secrets and credentials
- Monitoring data
- Log files
- Application state

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
   - Configuration rollback
   - Secret file recovery

---

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily
- Monitor notification channels for alerts
- Review backup success notifications
- Check system resource usage

#### Weekly
- Review Grafana dashboards for trends
- Check log rotation and archive sizes
- Verify sync operations are functioning

#### Monthly
- Run manual garbage collection if needed
- Review and update synchronized images
- Security update check for all containers
- Backup verification test

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
   - Always backup before changes
   - Test in dry-run mode where possible
   - Verify services after updates

---

## Troubleshooting

### Common Issues

#### Registry Not Accessible
1. Check Caddy status and logs:
   ```bash
   docker compose logs caddy
   ```
2. Verify DNS configuration
3. Check SSL certificate status
4. Verify firewall rules

#### Sync Failures
1. Check regsync logs:
   ```bash
   docker compose logs regsync
   ```
2. Verify credentials in secrets directory
3. Test network connectivity to source registries
4. Check disk space availability

#### Backup Failures
1. Verify SSH key permissions and accessibility
2. Check Hetzner Storage Box connectivity
3. Verify rsync command parameters
4. Check disk space on both source and destination

#### Performance Issues
1. Monitor resource usage via Grafana
2. Check Redis cache hit rates
3. Verify disk I/O performance
4. Review container resource limits

### Log Locations
- **Application Logs**: `/home/user/registry/logs/`
- **Container Logs**: `docker compose logs [service]`
- **System Logs**: `/var/log/` (via CrowdSec integration)
- **Archived Logs**: `/home/user/registry/logs/log_archive/`

### Diagnostic Commands
```bash
# Service status
docker compose ps

# Resource usage
docker stats

# Registry API check
curl -s https://registry.my_domain.tld/v2/_catalog

# Regsync status
docker compose exec regsync regsync -c /config/regsync.yml version

# Check disk usage
df -h /home/user/registry/
```

---

## Disaster Recovery

### Complete System Failure
1. **Prepare New System**:
   - Install Docker and Docker Compose
   - Configure user account and permissions
   - Set up SSH keys for backup access

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
   docker compose up -d
   ```

4. **Verification**:
   - Test registry accessibility
   - Verify all services are running
   - Check monitoring dashboards
   - Test image pull/push operations

### Partial Recovery Scenarios
- **Configuration corruption**: Restore from .bak files or backup
- **Data loss**: Selective restore from Hetzner backup
- **Service failure**: Container restart or image rebuild
- **Network issues**: DNS/firewall reconfiguration

### Recovery Time Objectives
- **RTO**: 4 hours for complete system recovery
- **RPO**: 24 hours (daily backup frequency)
- **Service availability**: 99.5% target uptime

---

## Conclusion

This private Docker registry setup represents a production-ready, enterprise-grade solution with comprehensive automation, monitoring, security, and operational procedures. The system is designed for reliability, maintainability, and scalability while providing complete visibility into all operations through extensive logging and notification systems.

Regular maintenance following the procedures outlined in this documentation will ensure optimal performance and reliability of the registry infrastructure.

---

*Documentation last updated: August 22, 2025*
*System version: v1.0*
