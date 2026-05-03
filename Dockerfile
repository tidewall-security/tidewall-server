FROM python:3.12-slim AS builder

ARG USE_ONNX=false

WORKDIR /build
RUN pip install --no-cache-dir --upgrade pip setuptools wheel

# Install dependencies into a virtual environment (cleaner than --prefix)
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml .
# Install CPU-only PyTorch first (avoids pulling 2GB+ CUDA variant)
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir .
RUN if [ "$USE_ONNX" = "true" ]; then pip install --no-cache-dir onnxruntime optimum; fi

# Pre-download all ML models into the image
ENV HF_HOME=/opt/models
ENV TRANSFORMERS_CACHE=/opt/models
ENV USE_ONNX=$USE_ONNX
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
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
