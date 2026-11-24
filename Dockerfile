# syntax=docker/dockerfile:1

# ---- Stage 1: build the frontend ----
FROM node:22-alpine AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: runtime (API + static SPA in one process) ----
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STATIC_DIR=/app/static \
    DATABASE_URL=sqlite:////data/magma.db

# git + ssh for the optional git repository sync of the rule configurations
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system magma && useradd --system --gid magma --home /app magma \
    && mkdir -p /data && chown magma:magma /data

WORKDIR /app
COPY backend/pyproject.toml ./
COPY backend/app ./app
RUN pip install .

COPY --from=frontend /build/dist ./static

USER magma
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/api/health', timeout=4).status == 200 else 1)"

# X-Forwarded-For/-Proto are trusted only from these addresses (uvicorn reads the variable).
# Set FORWARDED_ALLOW_IPS to your reverse proxy's address, e.g. in .env; never "*" when the
# port is reachable directly, or clients can fake their address in the audit log.
ENV FORWARDED_ALLOW_IPS=127.0.0.1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
