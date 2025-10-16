# syntax=docker/dockerfile:1

#####################################
# Build stage
#####################################
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
COPY app ./app
COPY scripts ./scripts
COPY clients ./clients
COPY dashboards ./dashboards
COPY README.md ./README.md
COPY .env.example ./

RUN pip install --no-cache-dir uv
RUN uv sync --frozen

#####################################
# Runtime stage
#####################################
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq-dev && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app /app

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/uv", "run", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
