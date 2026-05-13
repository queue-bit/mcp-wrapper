# syntax=docker/dockerfile:1
# -----------------------------------------------------------------------
# mcp-wrapper
# -----------------------------------------------------------------------
# Build (standard):
#   docker build -t mcp-wrapper .
#
# Build with optional extras:
#   docker build --build-arg EXTRAS="vault-aws" -t mcp-wrapper .
#   docker build --build-arg EXTRAS="vault-aws,vault-gcp" -t mcp-wrapper .
#
# Run (see docker-compose.yml for full setup):
#   docker run -p 127.0.0.1:8080:8080 \
#     -v ./config:/config:ro \
#     -v ./plugins:/app/plugins:ro \
#     -v mcp_data:/app/data \
#     --env-file .env \
#     mcp-wrapper
# -----------------------------------------------------------------------

FROM python:3.11-slim

# Optional comma-separated extras: "vault-aws", "vault-gcp", or "vault-aws,vault-gcp"
ARG EXTRAS=""

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# curl is used by the HEALTHCHECK; libffi/libssl are required by hvac (Vault client)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy only the files pip needs — maximises layer cache reuse when source changes
COPY pyproject.toml ./
COPY src/ ./src/

RUN if [ -n "$EXTRAS" ]; then \
        pip install -e ".[$EXTRAS]"; \
    else \
        pip install -e .; \
    fi

# Runtime directories:
#   /app/data    — named volume; holds audit.db (set db_path = "data/audit.db" in wrapper.toml)
#   /app/plugins — bind-mounted by operator; relative plugin paths in plugins.toml resolve here
RUN mkdir -p /app/data /app/plugins

# Non-root user for security
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp
RUN chown -R mcp:mcp /app
USER mcp

EXPOSE 8080

# GET /health requires no authentication
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# /config is the bind-mounted operator config directory
ENTRYPOINT ["mcp-wrapper", "--config", "/config"]
