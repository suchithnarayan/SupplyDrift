# SupplyDrift platform (FastAPI/uvicorn) — builds the React frontend, then serves
# the API + SPA. Build from the repo root:
#   docker build -f platform/Dockerfile -t supplydrift-platform .

# ── stage 1: build the SPA ───────────────────────────────────────────────────
# Base images are digest-pinned (the tag is kept for readability) so builds are
# reproducible and can't silently pull changed content. Refresh deliberately.
FROM node:24.18.0-trixie-slim@sha256:366fdef91728b1b7fa18c84fba63b6e79ed77b7e10cc206878e9705da4d7b169 AS frontend
WORKDIR /fe
COPY platform/frontend/package.json platform/frontend/package-lock.json ./
RUN npm ci
COPY platform/frontend/ ./
RUN npm run build

# ── stage 2: the API + bundled SPA ───────────────────────────────────────────
FROM python:3.13.14-slim-trixie@sha256:eb43ff125d8d58d7449dcba7d336c23bcac412f526d861db493b9994d8010280
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY platform/requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY platform/ ./
COPY --from=frontend /fe/dist ./frontend/dist

# Run as a non-root user; ensure persisted data and the shared runner-token
# mountpoint are writable by it before Docker initializes named volumes there.
RUN useradd --system --create-home --uid 10001 app \
 && mkdir -p /data /run/supplydrift \
 && chown -R app:app /data /run/supplydrift /app
USER app

ENV SUPPLYDRIFT_DB=/data/supplydrift.db \
    SUPPLYDRIFT_PUBLIC_URL=http://localhost:8765
EXPOSE 8765
# Single process (SQLite). The platform enqueues malware jobs on an interval when
# enabled; the malware-runner executes them. Set MALWARE_SCHEDULER=off to disable.
CMD ["python3", "run.py", "--host", "0.0.0.0", "--port", "8765"]
