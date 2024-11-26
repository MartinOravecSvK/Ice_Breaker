# Ice_Breaker

# Ubuntu x86 Development Environment in Docker

This repository contains all the files needed to set up an Ubuntu x86 environment using Docker, tailored for exploit development and compatible with ARM-based systems (e.g., M1 Macs).

## Prerequisites

- Docker Desktop installed on your machine.
- Ensure that Docker supports running images with `--platform=linux/386` (requires `qemu`).

## Setup Instructions (outdated)

### 1. Build the Docker Image

```bash
docker build -t x86_dev_env .
```

### 2. Run the Docker Container

```bash
docker run -it --rm --platform=linux/amd64 --name x86_dev_container x86_dev_env
```

Alternatively, use Docker Compose:

```bash
docker-compose up
```

### 3. Access the shell

```bash
docker-compose exec ubuntu-x86 bash
```

### 4. Create venv (inside the container)

```bash
python3 -m venv venv
```

### 5. Activate environment

```bash
source venv/bin/activate
```

### 6. Install dependencies

```bash
pip install -r requirements.txt
```



Commands to Build and Run the Docker Container
Clean Docker Build Cache

Run the following command to remove any existing Docker cache:

bash
Copy code
docker builder prune -a
This command removes all unused build cache and dangling images.

Build the Docker Image

Build your Docker image without using the cache:

bash
Copy code
docker-compose build --no-cache
Run the Docker Container

Start the Docker container:

bash
Copy code
docker-compose up -d
The -d flag runs the container in detached mode.

Attach to the Docker Container

Get a bash shell inside the running container:

bash
Copy code
docker-compose exec ubuntu-arm64 /bin/bash
Stop and Remove the Docker Container

When you're done, you can stop and remove the container:

bash
Copy code
docker-compose down