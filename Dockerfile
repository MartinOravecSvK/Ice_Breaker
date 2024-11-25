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
        make \
        wget \
        curl \
        build-essential \
        qemu-user \
        binutils \
        git && \
    apt-get clean

RUN pip3 install --no-cache-dir pwntools capstone

WORKDIR /workspace

CMD ["/bin/bash"]
