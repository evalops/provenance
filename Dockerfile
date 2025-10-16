# Base image
FROM python:3.12-slim

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Working directory
WORKDIR /app

# System dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev curl && \
    rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml uv.lock ./
COPY app ./app
COPY scripts ./scripts
COPY clients ./clients
COPY dashboards ./dashboards
COPY README.md ./README.md

# Install uv
RUN pip install --no-cache-dir uv

# Install dependencies
RUN uv sync --frozen

# Expose port
EXPOSE 8000

# Command
ENTRYPOINT ["/usr/local/bin/uv", "run", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
