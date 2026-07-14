# SupplyDrift scan RUNNER image.
#
# The runner does the heavy lifting — pull image layers + run syft to build the
# SBOM — then syncs the result to the platform. It is deliberately a SEPARATE
# image/resource from the platform (which is just a light API + UI over the DB).
#
# Build from the repo root:
#   docker build -f image-scanner/deploy/runner.Dockerfile -t supplydrift-runner:latest .
FROM ghcr.io/nolabs-ai/nono:0.67.1@sha256:8a877f3f79b1014bfe3b12a49a3e1c907caa123cc58c904c7d3cf1ae1e814b8a AS nono

FROM python:3.13.14-slim-trixie@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

# Copy only the sandbox binary from the official, digest-pinned image.
COPY --from=nono /usr/bin/nono /usr/local/bin/nono

# syft = SBOM engine; grype = vulnerability scanner (consumes the syft SBOM).
# Pin explicit versions and checksums so the runner doesn't silently install a new release.
ARG TARGETARCH
ARG SYFT_VERSION=1.46.0
ARG GRYPE_VERSION=0.115.0
ARG SYFT_LINUX_AMD64_SHA256=d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca
ARG SYFT_LINUX_ARM64_SHA256=9fafef4db4f032ce81008d3a1529985d41ceb6ccdf2b388c9ce2f1ed7d32082e
ARG GRYPE_LINUX_AMD64_SHA256=3fad92940650e514c0aa2dad83526942a055e210cec09a8a59d9c024adc2b90e
ARG GRYPE_LINUX_ARM64_SHA256=b8541b9ecc3e936e7db4ff14b71a9474b25f3898ccaad63ee0bfe3449fcd734d
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
      amd64) syft_sha="$SYFT_LINUX_AMD64_SHA256"; grype_sha="$GRYPE_LINUX_AMD64_SHA256" ;; \
      arm64) syft_sha="$SYFT_LINUX_ARM64_SHA256"; grype_sha="$GRYPE_LINUX_ARM64_SHA256" ;; \
      *) echo "unsupported TARGETARCH: $arch" >&2; exit 1 ;; \
    esac; \
    curl -sSfL -o /tmp/syft.tar.gz "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${arch}.tar.gz"; \
    echo "$syft_sha  /tmp/syft.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft; \
    curl -sSfL -o /tmp/grype.tar.gz "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${arch}.tar.gz"; \
    echo "$grype_sha  /tmp/grype.tar.gz" | sha256sum -c -; \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype; \
    rm -f /tmp/syft.tar.gz /tmp/grype.tar.gz \
 && rm -rf /var/lib/apt/lists/*

# Pre-bake the Grype DB and make it immutable at runtime. Updates happen only
# through a reviewed image rebuild, never from a hostile parser process.
ENV GRYPE_DB_CACHE_DIR=/opt/grype-db
RUN GRYPE_DB_AUTO_UPDATE=true grype db update \
 && touch /opt/grype-db/.supplydrift-readonly-canary \
 && find /opt/grype-db -type d -exec chmod 0555 {} + \
 && find /opt/grype-db -type f -exec chmod 0444 {} +
ENV GRYPE_DB_AUTO_UPDATE=false

# --- Extra tooling for Kubernetes / cloud sources (ON by default) -------------
# A single runner handles every "image" job — container registries AND
# Kubernetes / EKS — so kubectl + the AWS CLI ship in the image by default.
# Build a slim, registry-only runner by turning them off:
#   docker build --build-arg INSTALL_KUBECTL=false --build-arg INSTALL_AWSCLI=false ...
ARG INSTALL_AWSCLI=true
ARG INSTALL_KUBECTL=true
ARG AWSCLI_VERSION=2.35.21
ARG AWSCLI_LINUX_AMD64_SHA256=1fe665267a6149dfb8551cec52b419fa6e82533fab6dd7678939209246e792ee
ARG AWSCLI_LINUX_ARM64_SHA256=1d7a1f26a1bd9f0610663b7a4b571def6990692c8c66223ebe09ac2445787bcc
ARG KUBECTL_VERSION=v1.36.2
ARG KUBECTL_LINUX_AMD64_SHA256=1e9045ec32bea85da43de85f0065358529ea7c7a152eca78154fba5b58c27d82
ARG KUBECTL_LINUX_ARM64_SHA256=c957eb8c4bea27a3bb35b269edd9082e27f027f7b76b20b5bf4afebc726c6d3e

# AWS CLI (for ECR / ECS / EKS sources):
RUN if [ "$INSTALL_AWSCLI" = "true" ]; then \
      set -eux; \
      arch="${TARGETARCH:-amd64}"; \
      case "$arch" in \
        amd64) aws_arch="x86_64"; aws_sha="$AWSCLI_LINUX_AMD64_SHA256" ;; \
        arm64) aws_arch="aarch64"; aws_sha="$AWSCLI_LINUX_ARM64_SHA256" ;; \
        *) echo "unsupported TARGETARCH: $arch" >&2; exit 1 ;; \
      esac; \
      curl -sSfL "https://awscli.amazonaws.com/awscli-exe-linux-${aws_arch}-${AWSCLI_VERSION}.zip" -o /tmp/aws.zip \
   && echo "$aws_sha  /tmp/aws.zip" | sha256sum -c - \
   && cd /tmp && unzip -q aws.zip && ./aws/install && rm -rf /tmp/aws*; \
    fi

# kubectl (for Kubernetes / EKS sources — the k8s collector shells out to it):
RUN if [ "$INSTALL_KUBECTL" = "true" ]; then \
      set -eux; \
      arch="${TARGETARCH:-amd64}"; \
      case "$arch" in \
        amd64) kubectl_sha="$KUBECTL_LINUX_AMD64_SHA256" ;; \
        arm64) kubectl_sha="$KUBECTL_LINUX_ARM64_SHA256" ;; \
        *) echo "unsupported TARGETARCH: $arch" >&2; exit 1 ;; \
      esac; \
      curl -sSfL -o /usr/local/bin/kubectl \
        "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl" \
   && echo "$kubectl_sha  /usr/local/bin/kubectl" | sha256sum -c - \
   && chmod +x /usr/local/bin/kubectl; \
    fi
# ------------------------------------------------------------------------------

WORKDIR /app
COPY --chown=root:root supplydrift-sandbox/ /app/supplydrift-sandbox/
COPY --chown=root:root image-scanner/ /app/image-scanner/
RUN pip install --no-cache-dir --require-hashes -r /app/image-scanner/requirements.txt \
 && chmod -R a-w /app

WORKDIR /app/image-scanner

# Run as a non-root user (home /home/app matches the kubeconfig mount in compose).
# The runner processes untrusted image layers / cluster data, so it must not be root.
RUN useradd --system --create-home --uid 10001 app \
 && test "$(stat -c '%U:%G' /app/image-scanner/image_scan.py)" = "root:root" \
 && test "$(stat -c '%U:%G' /opt/grype-db)" = "root:root"
USER app

ENV PYTHONDONTWRITEBYTECODE=1 \
    SUPPLYDRIFT_TOOL_SANDBOX=required \
    SUPPLYDRIFT_SANDBOX_NETWORK=best-effort

# Defaults: pull the source list from the platform, emit JSON logs for aggregation.
# Secrets are supplied by the container ENV (the platform only stores their NAMES).
ENTRYPOINT ["python3", "image_scan.py"]
CMD ["--config-url", "http://supplydrift-platform:8765/api/scanner/config", "--log-format", "json"]
