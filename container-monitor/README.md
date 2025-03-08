Make sure the skopeo and jq are installed on the host

`sudo apt install skopeo jq -y`

How to Configure and Run:

Configuration via `config.sh` (for defaults): Edit `config.sh` to set default values for `LOG_LINES_TO_CHECK`, `CHECK_FREQUENCY_MINUTES`, `LOG_FILE`, and the `CONTAINER_NAMES_DEFAULT` array.

Configuration via Environment Variables (for overrides): Set environment variables before running the script to override the defaults from `config.sh`. For example:

```
export LOG_LINES_TO_CHECK=30
export CONTAINER_NAMES="nginx,app-container"
./docker-container-monitor.sh
```

Run the script:

`./docker-container-monitor.sh`: Monitors containers based on `config.sh` or `CONTAINER_NAMES` environment variable (or all running containers if no configuration).

`./docker-container-monitor.sh <container_name1> <container_name2> ...`: Monitors only the specified container names.

`./docker-container-monitor.sh logs`: Shows logs for all running containers.

`./docker-container-monitor.sh logs <container_name>`: Shows logs for a specific container.

Check the log file: Output is logged to the file specified by LOG_FILE (default docker-monitor.log).
