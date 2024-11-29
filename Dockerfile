FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Update and install essential tools
RUN apt-get update && \
    apt-get install -y \
        build-essential \
        gdb \
        gdb-multiarch \
        binutils \
        binutils-multiarch \
        qemu-user-static \
        python3 \
        python3-pip \
        python3-venv \
        strace \
        ltrace \
        elfutils \
        file \
        bsdmainutils \
        wget \
        curl \
        vim \
        git \
        cmake \
        netcat \
        socat \
        sudo \
    && apt-get clean

# Install Python libraries
RUN pip3 install --no-cache-dir --upgrade \
    pwntools \
    capstone \
    keystone-engine \
    unicorn \
    ropgadget

# Set working directory
WORKDIR /workspace

# Set default command
CMD ["/bin/bash"]
