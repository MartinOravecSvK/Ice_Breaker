FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
        build-essential \
        gdb \
        gdb-multiarch \
        binutils \
        python3 \
        python3-pip \
        python3-venv && \
    apt-get clean

RUN pip3 install --no-cache-dir --upgrade pwntools

WORKDIR /workspace
CMD ["/bin/bash"]
