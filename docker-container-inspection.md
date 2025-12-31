# Docker Container Filesystem Inspection

## Quick Reference: Node.js Containers (Distroless/Minimal)

### When `ls`, `sh`, or `bash` don't work

**Problem**: `exec failed: executable file not found in $PATH`  
**Cause**: Distroless or minimal base images (e.g., `gcr.io/distroless/nodejs`) don't include shell utilities

### Solution: Use Node.js as Shell Replacement

```bash
# List files in current directory
docker compose exec <service> node -e "console.log(require('fs').readdirSync('.'))"

# List files with details (size, permissions, etc.)
docker compose exec <service> node -e "const fs=require('fs'); fs.readdirSync('.').forEach(f => console.log(f, fs.statSync(f)))"

# Check specific directory
docker compose exec <service> node -e "console.log(require('fs').readdirSync('/app'))"

# Read file contents
docker compose exec <service> node -e "console.log(require('fs').readFileSync('package.json', 'utf8'))"

# Check environment PATH
docker compose exec <service> node -e "console.log(process.env.PATH)"

# List current working directory
docker compose exec <service> node -e "console.log(require('fs').readdirSync(process.cwd()))"
```

---

## Quick Reference: Generic Containers

### Standard inspection (when shell utilities ARE available)

```bash
# Enter interactive shell
docker compose exec <service> /bin/sh
# or if bash is available
docker compose exec <service> /bin/bash

# List files without entering shell
docker compose exec <service> ls -la /
docker compose exec <service> ls -la /app

# Check file exists
docker compose exec <service> test -f /path/to/file && echo "exists" || echo "missing"

# View file contents
docker compose exec <service> cat /path/to/file

# Find files by name
docker compose exec <service> find / -name "filename"

# Check running processes
docker compose exec <service> ps aux

# Check environment variables
docker compose exec <service> env
```


### Using standalone docker commands (non-compose)

```bash
# List running containers
docker ps

# Execute command in container
docker exec -it <container_id_or_name> /bin/sh
docker exec <container_id_or_name> ls -la /app

# View logs
docker logs <container_id_or_name>
docker logs -f <container_id_or_name>  # follow mode
```

---

## Universal Methods (Work for ALL containers)

### Method 1: Copy files from container to host

```bash
# Find container ID
docker compose ps -q <service>

# Copy entire directory out for inspection
docker cp $(docker compose ps -q <service>):/app ./temp-inspect
ls -la ./temp-inspect

# Copy single file
docker cp <container_id>:/path/to/file ./local-file
```


### Method 2: Inspect filesystem from host

```bash
# Find filesystem location on host
docker inspect $(docker compose ps -q <service>) | grep "MergedDir"

# The MergedDir path can be explored directly on your host (requires root)
```


### Method 3: Docker debug tool (Docker 1.25+)

```bash
# Attach debug container with full shell utilities
docker debug $(docker compose ps -q <service>)
```

---

## Diagnostic Commands

### Check what image you're using

```bash
# Via docker-compose
docker compose config | grep image

# Via docker inspect
docker inspect $(docker compose ps -q <service>) | grep Image

# Check image size (distroless usually <100MB)
docker images | grep <image_name>
```


### Identify container type

```bash
# Try shell (if this fails, it's minimal/distroless)
docker compose exec <service> /bin/sh -c "echo test"

# Check if common utilities exist
docker compose exec <service> which ls
docker compose exec <service> which bash
```

---

## Understanding Distroless/Minimal Images

**What are they?**

- Images containing ONLY the application runtime + dependencies
- No shell, no package managers, no GNU utilities
- Examples: `gcr.io/distroless/nodejs`, `gcr.io/distroless/python`, scratch-based images

**Benefits:**

- Reduced attack surface (no shell = harder to exploit)
- Smaller image size (often <50MB vs 200MB+)
- Faster startup and deployment

**Tradeoffs:**

- Cannot use traditional debugging tools
- Cannot `exec` into container with shell
- Requires alternative inspection methods

---

## Troubleshooting Workflow

1. **Try standard shell access first**

```bash
docker compose exec <service> /bin/sh
```

2. **If that fails, identify the runtime**
    - Node.js? Use the Node.js inspection methods above
    - Python? Try `python -c "import os; print(os.listdir('.'))"`
    - Go binary? Likely no runtime - use docker cp method
3. **Universal fallback: Copy files to host**

```bash
docker cp $(docker compose ps -q <service>):/app ./inspect
```

4. **For stopped containers**

```bash
# Create container from image without starting
docker create --name temp <image>
docker cp temp:/app ./inspect
docker rm temp
```

---

## Common Scenarios

### Check if node_modules is present

```bash
# Node.js container
docker compose exec <service> node -e "console.log(require('fs').existsSync('./node_modules'))"

# Standard container
docker compose exec <service> ls -la node_modules
```


### Verify environment variables

```bash
# Node.js container
docker compose exec <service> node -e "console.log(process.env)"

# Standard container
docker compose exec <service> env
```


### Check disk usage

```bash
# Node.js container
docker compose exec <service> node -e "const fs=require('fs'); console.log(fs.statSync('./'))"

# Standard container
docker compose exec <service> du -sh /app
```

---

## References

- [Docker Debug Slim Containers](https://iximiuz.com/en/posts/docker-debug-slim-containers/)
- [Exploring Distroless Images](https://mahesh-hegde.github.io/posts/distroless/)
- [Docker Distroless Blog](https://www.docker.com/blog/is-your-container-image-really-distroless/)
- [Docker Exec Documentation](https://docs.docker.com/reference/cli/docker/container/exec/)
