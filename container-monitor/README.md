# Docker Container Monitoring Script

A comprehensive Bash script to monitor Docker containers, including status, resource usage, image updates, and more, with color-coded output and summary reports.

### ✨ Features

-   **Container Health:** Checks running status, health checks (`healthy`/`unhealthy`), and restart counts.
-   **Resource Monitoring:** Monitors CPU and Memory usage against configurable thresholds.
-   **Disk Usage:** Checks disk space usage for container volumes and bind mounts, filtering out virtual/special paths like `/proc` and `/sys`.
-   **Network Health:** Checks for network errors and packet drops on container interfaces.
-   **Image Update Checks:** Uses `skopeo` to see if newer versions of your container images are available in their remote registries.
-   **Log Scanning:** Scans recent container logs for keywords like `error`, `panic`, `fail`, `fatal`.
-   **Summary Report:** Provides a final summary with:
    -   Host-level stats (Disk & Memory usage).
    -   A list of containers with issues, categorized with emojis (e.g., 🔄 for updates, 📜 for logs) for quick identification.

### ✅ Prerequisites

The script relies on a few common command-line tools.
-   `docker`
-   `jq` (for processing JSON)
-   `skopeo` (for checking container image updates)
-   `coreutils` (provides `timeout`)
-   `gawk` (provides `awk`)

For **Debian-based systems (e.g., Ubuntu)**, you can install the required tools using:

```bash
sudo apt-get update
sudo apt-get install -y skopeo jq coreutils gawk
```

### 🚀 Installation

1.  **Get the Script and Config File**

    Download the main script and a template configuration file:
    ```bash
    # Download the main script
    curl -o containers-monitor.sh https://raw.githubusercontent.com/buildplan/docker/refs/heads/main/container-monitor/containers-monitor.sh

    # Download the template config file
    curl -o config.sh https://raw.githubusercontent.com/buildplan/docker/refs/heads/main/container-monitor/config.sh
    ```
    **Note**: Always verify the content of scripts downloaded from the internet before executing them.

2.  **Make it Executable**

    Make the main script executable. The `config.sh` file only needs read permissions as it is sourced, not executed.
    ```bash
    chmod +x containers-monitor.sh
    ```

3.  **Customize Containers**

    List your Docker container names with `docker ps -a --format '{{.Names}}'`. Then, edit `config.sh` to add the names of the containers you want to monitor by default to the `CONTAINER_NAMES_DEFAULT` array.
    ```bash
    nano config.sh
    ```

### ⚙️ Configuration

The script can be configured in three ways, in the following order of precedence (1 overrides 2, which overrides 3):

1.  **Command-Line Arguments** (e.g., `./containers-monitor.sh traefik redis`)
2.  **Environment Variables** (e.g., `export CONTAINER_NAMES="traefik,redis"`)
3.  **`config.sh` File** (defines the default behavior)

The following settings can be configured via environment variables or by setting the `*_DEFAULT` value in `config.sh`:

| Environment Variable             | `config.sh` Variable                  | Default | Description                                                              |
| -------------------------------- | --------------------------------------- | ------- | ------------------------------------------------------------------------ |
| `CONTAINER_NAMES`                | `CONTAINER_NAMES_DEFAULT` (array)       | (empty) | Comma-separated string of container names to monitor.                    |
| `LOG_LINES_TO_CHECK`             | `LOG_LINES_TO_CHECK_DEFAULT`            | `20`    | Number of log lines to scan for errors.                                  |
| `CPU_WARNING_THRESHOLD`          | `CPU_WARNING_THRESHOLD_DEFAULT`         | `80`    | CPU usage % to trigger a warning.                                        |
| `MEMORY_WARNING_THRESHOLD`       | `MEMORY_WARNING_THRESHOLD_DEFAULT`      | `80`    | Memory usage % to trigger a warning.                                     |
| `DISK_SPACE_THRESHOLD`           | `DISK_SPACE_THRESHOLD_DEFAULT`          | `80`    | Disk usage % on a container mount to trigger a warning.                  |
| `NETWORK_ERROR_THRESHOLD`        | `NETWORK_ERROR_THRESHOLD_DEFAULT`       | `10`    | Number of network errors/drops on an interface to trigger a warning.     |
| `HOST_DISK_CHECK_FILESYSTEM`     | `HOST_DISK_CHECK_FILESYSTEM_DEFAULT`    | `/`     | Host filesystem path to check for the summary (e.g., `/` or `/var/lib/docker`). |
| `LOG_FILE`                       | `LOG_FILE_DEFAULT`                      | (script dir) | Path to the output log file.                                             |
| `CHECK_FREQUENCY_MINUTES`        | `CHECK_FREQUENCY_MINUTES_DEFAULT`       | `360`   | For documentation; intended for use with an external scheduler like cron. |

### 🏃‍♀️ Usage

-   **Run a full check with detailed output:**
    ```bash
    ./containers-monitor.sh
    ```

-   **Run a check on specific containers:**
    ```bash
    ./containers-monitor.sh traefik crowdsec
    ```

-   **Run in Summary-Only Mode (silent checks, only final summary is printed):**
    ```bash
    ./containers-monitor.sh summary
    ```
    You can also combine summary mode with specific containers:
    ```bash
    ./containers-monitor.sh summary traefik crowdsec
    ```

-   **View container logs:**
    ```bash
    # Show recent logs for a specific container
    ./containers-monitor.sh logs traefik

    # Show only error-related lines from a specific container's logs
    ./containers-monitor.sh logs errors traefik
    ```

-   **Save full logs to a file:**
    ```bash
    ./containers-monitor.sh save logs traefik
    ```

### 📊 Example Summary Output

```
[SUMMARY] -------------------------- Host System Stats ---------------------------
[SUMMARY]   Host Disk Usage (/): 34% used (Size: 25G, Used: 7.9G, Available: 16G)
[SUMMARY]   Host Memory Usage: Total: 1967MB, Used: 848MB (43%), Free: 132MB
[SUMMARY] ------------------- Summary of Container Issues Found --------------------
[SUMMARY] The following containers have warnings or errors:
[WARNING] - wiredoor 🔄 (Issues: Update)
[WARNING] - dozzle-agent 🔄 (Issues: Update)
[WARNING] - beszel-agent 📜 (Issues: Logs)
[SUMMARY] ------------------------------------------------------------------------
```

### 📝 Logging

All script output, including detailed per-container checks, is logged to the file specified by `LOG_FILE` (default: `docker-monitor.log` in the script's directory).

For long-term use, consider implementing log rotation (e.g., using `logrotate`) to manage the size of the log file.

### 🔧 Troubleshooting

-   **Permissions:** Ensure the script is executable (`chmod +x containers-monitor.sh`). If you get "Permission denied" errors for Docker commands, ensure the user running the script has permission to access the Docker socket.
-   **Logs:** If the script doesn't behave as expected, check the contents of the log file for detailed error messages.
-   **Dependencies:** Verify that Docker is running and that `jq`, `skopeo`, `awk`, and `timeout` are installed and available in the system's `PATH`.
-   **Container Names:** Double-check that the container names in `config.sh` or environment variables exactly match the running containers.
