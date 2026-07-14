# SupplyDrift GitHub repository scan RUNNER.
#
# Clones repositories (public anonymously, private with a PAT), runs the phantom-
# dependency scanner PLUS syft (declared deps) + grype (CVEs), deduped into one
# payload, and syncs to the platform.
#
# Build from the repo root:
#   docker build -f github-shadow-deps/deploy/runner.Dockerfile -t supplydrift-github-runner:latest .
FROM ghcr.io/nolabs-ai/nono:0.67.1@sha256:8a877f3f79b1014bfe3b12a49a3e1c907caa123cc58c904c7d3cf1ae1e814b8a AS nono

FROM python:3.13.14-slim-trixie@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280

# Copy only the sandbox binary from the official, digest-pinned image.
COPY --from=nono /usr/bin/nono /usr/local/bin/nono

# git = clone; syft = declared-dependency SBOM; grype = CVEs over the syft SBOM.
# Pin explicit versions and checksums so the runner doesn't silently install a new release.
ARG TARGETARCH
ARG SYFT_VERSION=1.46.0
ARG GRYPE_VERSION=0.115.0
ARG SYFT_LINUX_AMD64_SHA256=d654f678b709eb53c393d38519d5ed7d2e57205529404018614cfefa0fb2b5ca
ARG SYFT_LINUX_ARM64_SHA256=9fafef4db4f032ce81008d3a1529985d41ceb6ccdf2b388c9ce2f1ed7d32082e
ARG GRYPE_LINUX_AMD64_SHA256=3fad92940650e514c0aa2dad83526942a055e210cec09a8a59d9c024adc2b90e
ARG GRYPE_LINUX_ARM64_SHA256=b8541b9ecc3e936e7db4ff14b71a9474b25f3898ccaad63ee0bfe3449fcd734d
RUN apt-get update \
 && apt-get install -y --no-install-recommends git curl ca-certificates \
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

WORKDIR /app
COPY --chown=root:root supplydrift-sandbox/ /app/supplydrift-sandbox/
COPY --chown=root:root github-shadow-deps/ /app/github-shadow-deps/
RUN pip install --no-cache-dir --require-hashes -r /app/github-shadow-deps/requirements.txt \
 && chmod -R a-w /app

WORKDIR /app/github-shadow-deps

# Run as a non-root user — the runner clones and scans untrusted repositories.
RUN useradd --system --create-home --uid 10001 app \
 && test "$(stat -c '%U:%G' /app/github-shadow-deps/gbom_sync.py)" = "root:root" \
 && test "$(stat -c '%U:%G' /opt/grype-db)" = "root:root"
USER app

ENV PYTHONDONTWRITEBYTECODE=1 \
    SUPPLYDRIFT_TOOL_SANDBOX=required \
    SUPPLYDRIFT_SANDBOX_NETWORK=best-effort

# Pulls the `github` source list from the platform; secrets (a classic PAT for
# private repos) come from the container env (the platform stores only the name).
ENTRYPOINT ["python3", "gbom_sync.py"]
CMD ["--config-url", "http://supplydrift-platform:8765/api/scanner/config", "--log-format", "json"]
