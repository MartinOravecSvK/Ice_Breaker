# Ice_Breaker

# Ubuntu x86 Development Environment in Docker

This repository contains all the files needed to set up an Ubuntu x86 environment using Docker, tailored for exploit development and compatible with ARM-based systems (e.g., M1 Macs).

## Prerequisites

- Docker Desktop installed on your machine.
- Ensure that Docker supports running images with `--platform=linux/386` (requires `qemu`).

## Setup Instructions

### 1. Build the Docker Image

```bash
docker build -t ubuntu-x86 .
```

### 2. Run the Docker Container

```bash
docker run --platform=linux/386 -it --rm -v $(pwd):/workspace ubuntu-x86
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