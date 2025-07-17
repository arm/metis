FROM python:3.12-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential clang llvm lld python3-distutils git wget unzip && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip setuptools wheel && \
    pip3 install atheris pyinstaller

ENV SRC=/src \
    OUT=/out

WORKDIR $SRC

COPY . $SRC
