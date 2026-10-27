# AgentGuard Security Suite Dockerfile
FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8765

WORKDIR /app

# Install system dependencies (curl for healthchecks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY agentguard/ /app/agentguard/
COPY web/ /app/web/
COPY run.py /app/run.py
COPY tests/ /app/tests/

# Run unit tests to verify integrity before exposing container
RUN python -m unittest discover -s tests -v

# Create non-privileged service user
RUN useradd -m -u 1001 agentguard && \
    chown -R agentguard:agentguard /app

USER agentguard

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8765/api/metrics || exit 1

ENTRYPOINT ["python", "run.py"]
CMD ["8765"]
