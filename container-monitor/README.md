## A simple script to monitor docker resources, logs and check for new images/updates. 

### Prerequisites:
  - Docker
  - jq (for processing JSON output from docker inspect and docker stats)
  - skopeo (for checking for container image updates)
  - (Optional) numfmt: for human-readable formatting in future enhancements (not currently used)

`sudo apt install skopeo jq -y`

### Get this script 

`curl -o container-monitor.sh https://raw.githubusercontent.com/buildplan/docker/refs/heads/main/container-monitor/container-monitor.sh`

`curl -o config.sh https://raw.githubusercontent.com/buildplan/docker/refs/heads/main/container-monitor/config.sh`

#### Make Executable

`chmod +x container-monitor.sh config.sh`

#### Get the docker container name 

`docker ps -a --format '{{.Names}}'`

Add the names in config `nano config.sh`

### How to Configure and Run:

Configuration via `config.sh` (for defaults): Edit `config.sh` to set default values for `LOG_LINES_TO_CHECK`, `CHECK_FREQUENCY_MINUTES`, `LOG_FILE`, and the `CONTAINER_NAMES_DEFAULT` array.

Configuration via Environment Variables (for overrides): Set environment variables before running the script to override the defaults from `config.sh`. For example:

```
export LOG_LINES_TO_CHECK=30
export CONTAINER_NAMES="nginx,app-container"
./docker-container-monitor.sh
```

### Run the script:

`./docker-container-monitor.sh`: Monitors containers based on `config.sh` or `CONTAINER_NAMES` environment variable (or all running containers if no configuration).

`./docker-container-monitor.sh <container_name1> <container_name2> ...`: Monitors only the specified container names.

`./docker-container-monitor.sh logs`: Shows logs for all running containers.

`./docker-container-monitor.sh logs <container_name>`: Shows logs for a specific container.

Check the log file: Output is logged to the file specified by `LOG_FILE` (default `docker-monitor.log`).
