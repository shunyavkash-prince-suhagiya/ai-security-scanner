# syntax=docker/dockerfile:1

FROM python:3.11-slim AS builder
WORKDIR /app
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY platform/requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv && /opt/venv/bin/pip install -r /tmp/requirements.txt

FROM python:3.11-slim AS runtime
WORKDIR /app
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UPLOAD_DIR=/tmp/security-scanner/uploads \
    REPORTS_DIR=/tmp/security-scanner/reports

RUN useradd --create-home appuser && \
    mkdir -p "$UPLOAD_DIR" "$REPORTS_DIR" && \
    chown -R appuser:appuser /app /tmp/security-scanner

COPY --from=builder /opt/venv /opt/venv
COPY src /app/src
COPY platform /app/platform

USER appuser
EXPOSE 8000
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "2", "-b", "0.0.0.0:8000", "platform.api.main:app"]
