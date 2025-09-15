# Container Registry Monitor Script - Usage Instructions

## **Basic Usage**

```bash
./registry_check.sh [OPTIONS]
```

## **Command Options**

| Option | Description |
|--------|-------------|
| `--detailed` | Send detailed change information (default) |
| `--summary` | Send summary of changes only |
| `--mini` | Send minimal notification |
| `--minimal` | Same as `--mini` |
| `--quiet`, `-q` | Suppress all output except errors |
| `-h`, `--help` | Show help message with color legend |

## **Usage Examples**

### **Interactive Monitoring**
```bash
# Default detailed notifications with colors
./registry_check.sh

# Get quick summary
./registry_check.sh --summary

# Minimal notifications  
./registry_check.sh --mini

# Show help with color legend
./registry_check.sh --help
```

### **Automation & Cron Jobs**
```bash
# Quiet mode for cron - only errors logged
./registry_check.sh --quiet

# Summary mode for scheduled checks
./registry_check.sh --summary --quiet
```

## **Deployment Examples**

### **Cron Job Setup**
```bash
# Every 5 minutes, quiet mode
*/5 * * * * /path/to/registry_check.sh --quiet

# Hourly summary during business hours
0 9-17 * * 1-5 /path/to/registry_check.sh --summary

# Daily detailed report at 8 AM
0 8 * * * /path/to/registry_check.sh --detailed
```

### **CI/CD Integration**
```bash
# Minimal notifications in pipelines
./registry_check.sh --mini --quiet

# Check with specific notification level
./registry_check.sh --summary
```

## **Color Legend** (Terminal Only)
- **🟢 +** New repositories
- **🔴 -** Removed repositories  
- **🟡 ~** Updated repositories

## **Required Setup Files**
Create these files in `./secrets/` directory:
- `registry_host` - Your registry hostname
- `ntfy_url` - Your ntfy server URL
- `ntfy_topic` - Your ntfy topic
- `ntfy_token` - Your ntfy auth token

## **Log Files**
- Main log: `./logs/check_changes.log`
- State file: `./logs/.check_changes_state`

## **Exit Codes**
- `0` - Success (changes detected or no changes)
- `1` - Error (registry connection failed, ntfy failed, etc.)

## **Output Modes**

### **Detailed Mode** (Default)
```
Registry Changes on hostname

SUMMARY:
New: 1 repos
Removed: 0 repos
Updated: 2 repos

NEW REPOS:
+ app/frontend

UPDATED REPOS:
~ app/backend (+2/-1 tags)
~ database/postgres (+1/-0 tags)
```

### **Summary Mode**
```
Registry Update on hostname

3 repositories changed
4 total tag changes
```

### **Minimal Mode**
```
Registry changes on hostname: 3 repos updated
```

## **Best Practices**
- Use `--quiet` for automated monitoring
- Use `--summary` for regular scheduled reports
- Use `--detailed` for interactive troubleshooting
- Set up different cron jobs for different notification levels
- Monitor the log files for any connection issues

-----

## **Deployment Recommendations:**

### **1. Set up as a cron job:**
```bash
# Every 5 minutes, quiet mode
*/5 * * * * /path/to/registry_check.sh --quiet

# Hourly summary during business hours  
0 9-17 * * 1-5 /path/to/registry_check.sh --summary
```

### **2. For interactive monitoring:**
```bash
# Watch with colors
./registry_check.sh

# Quick summary
./registry_check.sh --summary
```

### **3. For CI/CD integration:**
```bash
# Minimal notifications in pipelines
./registry_check.sh --mini --quiet
```
