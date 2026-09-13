FROM ubuntu:24.04

LABEL maintainer="Threat Research Sandbox"
LABEL description="Air-gapped Linux detonation sandbox with embedded Velociraptor triage"

ENV DEBIAN_FRONTEND=noninteractive

# Install common execution runtime dependencies and utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    file \
    procps \
    cron \
    zip \
    unzip \
    tar \
    net-tools \
    iproute2 \
    strace \
    python3 \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Download standalone Velociraptor CLI for Linux
ARG VELOCIRAPTOR_VERSION=v0.74.0
RUN wget -q "https://github.com/Velocidex/velociraptor/releases/download/v0.74/velociraptor-${VELOCIRAPTOR_VERSION}-linux-amd64" \
    -O /usr/local/bin/velociraptor || \
    wget -q "https://github.com/Velocidex/velociraptor/releases/download/v0.73/velociraptor-v0.73.0-linux-amd64" \
    -O /usr/local/bin/velociraptor || true

RUN if [ -f /usr/local/bin/velociraptor ]; then chmod +x /usr/local/bin/velociraptor; fi

# Create sandbox directories
RUN mkdir -p /sandbox/input /sandbox/output /sandbox/work

WORKDIR /sandbox

COPY entrypoint.sh /sandbox/entrypoint.sh
RUN chmod +x /sandbox/entrypoint.sh

ENTRYPOINT ["/sandbox/entrypoint.sh"]
