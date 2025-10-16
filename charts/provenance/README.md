# Provenance Helm Chart

Deploys the Provenance & Risk Analytics service and an optional Redis instance.

## Prerequisites

- Kubernetes 1.23+
- Helm 3+

## Getting Started

```bash
helm install provenance charts/provenance \ 
  --set image.repository=ghcr.io/your-org/provenance \
  --set image.tag=latest
```

To enable the bundled Redis dependency, leave `redis.enabled=true` (default). Provide external Redis by setting `redis.enabled=false` and overriding `PROVENANCE_REDIS_URL` via `values.yaml` or `--set`.

Expose the service via Ingress:

```bash
helm install provenance charts/provenance \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=provenance.example.com \
  --set ingress.hosts[0].paths[0].path=/ \
  --set ingress.hosts[0].paths[0].pathType=Prefix
```

## Configuration

See `values.yaml` for configurable options including environment variables, resources, and OTEL settings.
