# Dockerfile - multi-stage build with normal ARG/ENV usage.
# No secrets in ARG or ENV (only non-sensitive build metadata).

FROM python:3.11-slim AS builder

# Non-sensitive build arguments only
ARG APP_VERSION=1.0.0
ARG BUILD_DATE
ARG GIT_COMMIT=unknown

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# Non-sensitive runtime environment variables
ENV APP_ENV=production
ENV PORT=8080
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy installed packages from builder stage
COPY --from=builder /root/.local /root/.local

WORKDIR /app
COPY . .

# Drop to non-root user
RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["python", "app.py"]
