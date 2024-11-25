FROM --platform=linux/x86_64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
        libc6:i386 \
        gcc-multilib \
        g++-multilib \
        gdb \
        python3 \
        python3-pip \
        python3-venv \
        make \
        wget \
        curl \
        build-essential \
        qemu-user \
        binutils \
        git && \
    apt-get clean

WORKDIR /workspace

CMD ["/bin/bash"]
