# SHADOW: FROM with mutable :latest tag
FROM ubuntu:latest

# SHADOW: FROM with mutable :main tag
FROM node:main

# SAFE: FROM pinned to digest
# FROM alpine@sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380c

# SHADOW: apt-get is fine in Dockerfile context (LOW for CI, but not for dockerfile)
RUN apt-get update && apt-get install -y curl wget

# SHADOW: curl | bash inside Dockerfile (CRITICAL)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -

# SHADOW: direct binary download
RUN curl -Lo /usr/local/bin/kubectl https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl && \
    chmod +x /usr/local/bin/kubectl

# SHADOW: FROM with no tag at all (implicitly :latest)
FROM python

WORKDIR /app

# SHADOW REFERENCE: Dockerfile copies a script (reference tracking)
COPY scripts/setup.sh /app/setup.sh
RUN chmod +x /app/setup.sh

COPY . .
