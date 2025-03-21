## Docker Containers Monitoring Script

A simple script to monitor Docker resources, logs, and check for new images/updates.

### Prerequisites:

- Docker
- jq (for processing JSON output from docker inspect and docker stats)
- skopeo (for checking for container image updates)
- (Optional) numfmt: for human-readable formatting in future enhancements (not currently used)

For Debian-based systems (e.g., Ubuntu), you can install the required tools using:

```bash
sudo apt install skopeo jq -y
```

### Get the Script

Download the script and configuration file using the following commands:

```bash
curl -o containers-monitor.sh https://raw.githubusercontent.com/buildplan/docker/refs/heads/main/container-monitor/containers-monitor.sh
```
```bash
curl -o config.sh https://raw.githubusercontent.com/buildplan/docker/refs/heads/main/container-monitor/config.sh
```

**Note**: Always verify the integrity of downloaded scripts, especially when downloading from the internet.

### Make Executable

Make the scripts executable with the following command:

```bash
chmod +x containers-monitor.sh config.sh
```

### Get Docker Container Names

List all Docker container names with:

```bash
docker ps -a --format '{{.Names}}'
```

Add the relevant container names to the `config.sh` file using a text editor:

```bash
nano config.sh
```

### How to Configure and Run:

**Configuration via `config.sh`**:

- Edit `config.sh` to set default values for `LOG_LINES_TO_CHECK`, `CHECK_FREQUENCY_MINUTES`, `LOG_FILE`, and the `CONTAINER_NAMES_DEFAULT` array.

**Configuration via Environment Variables**:

- Set environment variables before running the script to override the defaults from `config.sh`. For example:

```bash
export LOG_LINES_TO_CHECK=30
export CONTAINER_NAMES="nginx,app-container"
./containers-monitor.sh
```

### Run the Script:

- `./containers-monitor.sh`: Monitors containers based on `config.sh` or `CONTAINER_NAMES` environment variable (or all running containers if no configuration).

- `./container-monitor.sh <container_name1> <container_name2> ...`: Monitors only the specified container names.

- `./containers-monitor.sh logs`: Shows logs for all running containers.

- `./containers-monitor.sh logs <container_name>`: Shows logs for a specific container.
  
- `./containers-monitor.sh logs errors <container_name>`: Displays only the error messages from the logs of a specific container.

- `./docker-container-monitor.sh save logs <container_name>`: Save logs for a specific container to a file

### Logging:

Output is logged to the file specified by `LOG_FILE` (default `docker-monitor.log`). Consider implementing log rotation to manage the size of the log file over time.

### Troubleshooting:

- If you encounter issues, check the log file for detailed error messages.
- Ensure that Docker is running and that the required tools (`jq`, `skopeo`) are installed.
- Verify that the container names in `config.sh` are correct and match the running containers.

