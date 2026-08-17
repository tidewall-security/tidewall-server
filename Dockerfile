FROM python:3.12-slim AS builder


WORKDIR /build
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install dependencies into a virtual environment (cleaner than --prefix)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Everything Hatch needs to build the project. `pip install .` reads the
# readme, licence and notice declared in pyproject metadata and packages the
# `app` wheel target, so copying pyproject alone failed with
# "Readme file does not exist: README.md" before installing anything.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY app ./app

# Install CPU-only PyTorch first (avoids pulling 2GB+ CUDA variant)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir .

# Pre-download all ML models into the image. prewarm.py reads
# app/model_registry.py for the pinned revisions, so `app` must already be
# present — it is, from the copy above.
ENV HF_HOME=/opt/models
ENV TRANSFORMERS_CACHE=/opt/models
COPY prewarm.py .
RUN python prewarm.py

# ---- Runtime stage ----
FROM python:3.12-slim
WORKDIR /app

# Copy virtual environment and pre-downloaded models
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /opt/models /opt/models

ENV PATH="/opt/venv/bin:$PATH"
ENV HF_HOME=/opt/models
ENV TRANSFORMERS_CACHE=/opt/models
ENV TOKENIZERS_PARALLELISM=false
ENV PYTHONUNBUFFERED=1

# Copy application code
COPY app/ /app/app/
COPY policy.yaml /app/policy.yaml
COPY alembic.ini /app/alembic.ini
COPY alembic/ /app/alembic/

# Create non-root user and data directory
RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appgroup /app/data

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"]

USER appuser

EXPOSE 8080
# Launch through the package entry point rather than the uvicorn CLI: the
# bind address must come from validated settings, or the insecure-mode guard
# checks a value the server does not use.
CMD ["python", "-m", "app"]
