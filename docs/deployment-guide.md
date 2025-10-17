# Deployment & Operations Guide

This guide outlines supported deployment patterns for Provenance, from local Docker runs to production-ready Kubernetes clusters, and highlights operational concerns such as scaling detectors, managing secrets, and monitoring.

## Architecture Overview

Core services:

- **API** – FastAPI application (ASGI) served by `uvicorn`.
- **Redis** – Primary datastore for analyses, findings, and decisions.
- **Optional analytics sinks** – ClickHouse, Snowflake, BigQuery, or file-based JSONL exports.
- **Optional observability** – Prometheus/OTLP exporters for metrics.

Background work (detector execution, governance, analytics) happens inline today; no external workers are required.

## Local & Docker Compose

Use Docker when validating changes locally or running against mocked dependencies:

```bash
docker compose up --build
```

The compose stack includes:

- API container (`provenance-api`) exposing `8000`.
- Redis (`redis:7-alpine`) with a persistent volume.
- Optional ClickHouse (if you enable `docker-compose.clickhouse.yml`).

Override environment variables in `.env` or `docker-compose.override.yml`. See the [Configuration Reference](configuration.md) for available settings.

## Container Image

Build a production image with:

```bash
docker build -t your-registry/provenance:<tag> .
```

Key build arguments:

- `UV_LOCKFILE=uv.lock` – Install pinned dependencies.
- `TARGET_ENV=production` – (Optional) adjust if you customize the Dockerfile stages.

Run the container:

```bash
docker run --rm \
  -p 8000:8000 \
  -e PROVENANCE_REDIS_URL=redis://host.docker.internal:6379/0 \
  your-registry/provenance:<tag>
```

## Kubernetes (Helm/Manifests)

There is no bundled Helm chart yet, but a basic deployment involves:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: provenance-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: provenance-api
  template:
    metadata:
      labels:
        app: provenance-api
    spec:
      containers:
        - name: api
          image: your-registry/provenance:<tag>
          imagePullPolicy: IfNotPresent
          ports:
            - name: http
              containerPort: 8000
          envFrom:
            - configMapRef:
                name: provenance-config
            - secretRef:
                name: provenance-secrets
          readinessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 10
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 30
            periodSeconds: 30
          resources:
            requests:
              cpu: 250m
              memory: 512Mi
            limits:
              cpu: 1
              memory: 1Gi
```

- Provide Redis as a managed service (e.g., AWS Elasticache) and set `PROVENANCE_REDIS_URL` accordingly.
- Mount ConfigMaps/Secrets for policy thresholds, API tokens, signing keys, and GitHub credentials.
- Use a HorizontalPodAutoscaler to scale API pods based on CPU or custom metrics.

### Ingress & TLS

- Expose the API via an ingress controller (NGINX, Traefik, ALB).
- Terminate TLS at the ingress or use a service mesh (Linkerd, Istio). Ensure `PROVENANCE_SERVICE_BASE_URL` matches the external HTTPS endpoint.

## Scaling Considerations

- **Detector Throughput** – Detector execution happens synchronously per request. Increase pod count to parallelize analyses, or shard workflows by repo/team. Monitoring request latency via Prometheus helps identify bottlenecks.
- **Redis Capacity** – Tune persistence and memory policy. For large analyses, configure snapshotting and `maxmemory-policy` (e.g., `volatile-lru`) to avoid eviction of hot keys.
- **Background Tasks** – FastAPI `BackgroundTasks` are used for asynchronous operations (analytics writes). Ensure pods have enough CPU headroom to handle background work without delaying responses.
- **Analytics Warehouse** – When using ClickHouse/Snowflake/BigQuery, provision connectivity (service accounts, network policies) and monitor ingest failure logs.

## Observability

- Enable Prometheus exporter by installing the `opentelemetry-exporter-prometheus` package and setting `PROVENANCE_OTEL_ENABLED=true`, `PROVENANCE_OTEL_EXPORTER=prometheus`.
- Scrape `/metrics` and create alerts on:
  - Request latency (P95 > SLO).
  - Detector capability mismatches.
  - Decision outcome imbalance (e.g., spike in `block`).
- For OTLP, configure `PROVENANCE_OTEL_ENDPOINT` and deploy a collector.

## Secrets Management

- Store API tokens, signing keys, and GitHub credentials in Kubernetes Secrets, HashiCorp Vault, AWS Secrets Manager, etc.
- Encode Ed25519 signing keys in base64 before storing (matches app expectations).
- Rotate secrets regularly and redeploy pods to refresh environment variables.

## Disaster Recovery

- Redis is the system of record for analyses. Enable AOF/RDB snapshots and backup to durable storage.
- Export DSSE decision bundles to long-term storage (S3, GCS) via CI to preserve audit trails.
- For analytics warehouses, rely on built-in backups; events can always be regenerated by replaying DSSE bundles and analysis inputs if needed.

## Deployment Checklist

1. Configure `PROVENANCE_*` variables (see [Configuration Reference](configuration.md)).
2. Provision Redis with sufficient memory and persistence.
3. Deploy API (Docker/K8s) with health checks and readiness probes.
4. Configure ingress/TLS and update `PROVENANCE_SERVICE_BASE_URL`.
5. Wire CI to submit analyses (see [CI Integration Guide](ci-integration.md)).
6. Enable observability exporters and set up dashboards/alerts.
7. Archive DSSE bundles and SARIF outputs for compliance/audits.
