## Deploying Dozzle as a Central Hub and Connecting Agents

Dozzle is a real-time log viewer for Docker containers. This guide demonstrates how to set up a central Dozzle instance (the hub) and connect Dozzle agents running on other systems to it.

**Prerequisites:**

* Docker and Docker Compose installed on your hub system.
* Docker installed on the agent systems.
* Network connectivity between the hub and agent systems.

**Step 1: Deploying the Dozzle Hub**

1.  **Create a `docker-compose.yml` file:**

    Create a file named `docker-compose.yml` on your hub system with the following content:

    ```yaml

    services:
      dozzle:
        image: amir20/dozzle:latest
        ports:
          - "8080:8080"
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock:ro
        environment:
          - DOZZLE_BASE=/dozzle/
          - DOZZLE_PORT=8080
          - DOZZLE_HUB=true
    ```

    **Explanation:**

    * `image: amir20/dozzle:latest`: Uses the latest Dozzle image.
    * `ports: "8080:8080"`: Exposes Dozzle on port 8080 of the host.
    * `volumes: /var/run/docker.sock:/var/run/docker.sock:ro`: Mounts the Docker socket, allowing Dozzle to access container logs.
    * `environment:`: Sets environment variables:
        * `DOZZLE_BASE=/dozzle/`: Sets the base URL path for Dozzle.
        * `DOZZLE_PORT=8080`: Specifies the port Dozzle listens on.
        * `DOZZLE_HUB=true`: Enables hub mode.

2.  **Start the Dozzle hub:**

    Navigate to the directory containing `docker-compose.yml` and run:

    ```bash
    docker-compose up -d
    ```

3.  **Access the Dozzle hub:**

    Open your web browser and navigate to `http://<hub-ip>:8080/dozzle/`. You should see the Dozzle interface.

**Step 2: Deploying Dozzle Agents**

1.  **Create a `docker-compose.yml` file:**

    On each agent system, create a `docker-compose.yml` file with the following content:

    ```yaml
    
    services:
      dozzle-agent:
        image: amir20/dozzle:latest
        volumes:
          - /var/run/docker.sock:/var/run/docker.sock:ro
        environment:
          - DOZZLE_HUB_URL=http://<hub-ip>:8080/dozzle/
          - DOZZLE_HOSTNAME=<agent-hostname>
    ```

    **Explanation:**

    * `image: amir20/dozzle:latest`: Uses the latest Dozzle image.
    * `volumes: /var/run/docker.sock:/var/run/docker.sock:ro`: Mounts the Docker socket.
    * `environment:`: Sets environment variables:
        * `DOZZLE_HUB_URL=http://<hub-ip>:8080/dozzle/`: Specifies the URL of the Dozzle hub. Replace `<hub-ip>` with the IP address of your hub system.
        * `DOZZLE_HOSTNAME=<agent-hostname>`: Sets the hostname of the agent system. Replace `<agent-hostname>` with a unique identifier for the agent (e.g., the hostname or a custom name).

2.  **Start the Dozzle agent:**

    Navigate to the directory containing `docker-compose.yml` and run:

    ```bash
    docker-compose up -d
    ```

**Step 3: Viewing Logs in the Dozzle Hub**

1.  **Refresh the Dozzle hub:**

    Refresh the Dozzle hub web interface (`http://<hub-ip>:8080/dozzle/`).

2.  **Select the agent:**

    You should now see the hostname of the agent system in the Dozzle interface's dropdown menu. Select the agent's hostname to view the logs from that system.

3.  **View container logs:**

    You can now select and view the logs of the Docker containers running on the agent system.

**Important Considerations:**

* **Security:** Exposing the Docker socket can be a security risk. Ensure that your network is properly secured. Consider using a reverse proxy with authentication for the Dozzle hub.
* **Network Configuration:** Ensure that the agent systems can reach the Dozzle hub on port 8080. Firewalls or network configurations may need to be adjusted.
* **Hostname Uniqueness:** Use unique hostnames for each agent to avoid conflicts in the Dozzle hub.
* **Persistent Configuration:** For production environments, consider using Docker volumes to persist Dozzle's configuration and data.
* **TLS/SSL:** Configure TLS/SSL for secure communication between the agents and the hub, especially if transmitting data over untrusted networks.
* **Authentication:** Implement authentication for the Dozzle Hub to restrict access. This can be done with traefik, nginx, or other reverse proxies.

