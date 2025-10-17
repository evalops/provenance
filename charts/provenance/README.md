# Provenance Helm Chart

Deploys the Provenance & Risk Analytics API with optional managed Redis, ingress, autoscaling, and tunable environment settings.

## Prerequisites

- Kubernetes 1.23+
- Helm 3.8+

## Installing

```bash
helm install provenance charts/provenance \
  --set image.repository=ghcr.io/your-org/provenance \
  --set image.tag=latest
```

Common overrides:

- `--set env.PROVENANCE_SERVICE_BASE_URL=https://provenance.example.com` to align generated links with your ingress.
- `--set redis.enabled=false --set env.PROVENANCE_REDIS_URL=redis://redis.example.com:6379/0` to reuse an external Redis cluster.
- `--set ingress.enabled=true --set ingress.hosts[0].host=provenance.example.com` to expose the service publicly.

## Values

| Key | Description | Default |
| --- | --- | --- |
| `replicaCount` | API replicas (ignored when `autoscaling.enabled=true`) | `2` |
| `image.repository` | Container image repository | `evalops/provenance` |
| `serviceAccount.create` | Create a service account automatically | `true` |
| `env` | Base environment variables for the API container | `{ PROVENANCE_SERVICE_BASE_URL: http://provenance:8000 }` |
| `extraEnv` / `extraEnvFrom` | Additional env pairs or references (ConfigMap/Secret) | `[]` |
| `resources` | CPU/memory requests & limits | `{}` |
| `livenessProbe` & `readinessProbe` | HTTP probes served from `/healthz` | Enabled |
| `autoscaling.enabled` | HorizontalPodAutoscaler toggle | `false` |
| `ingress.*` | Ingress configuration (class, hosts, TLS) | Disabled |
| `redis.enabled` | Deploy bundled Redis | `true` |
| `redis.persistence.enabled` | Provision PVC for Redis data | `false` |

See [`values.yaml`](values.yaml) for the full catalog (node selectors, tolerations, OTEL knobs, extra volumes, etc.).

## Upgrade Notes

- When enabling Redis persistence, ensure an appropriate storage class exists.
- Provide signing keys and API tokens via `extraEnvFrom` referencing Kubernetes Secrets.
- Enable autoscaling by toggling `autoscaling.enabled` and configuring min/max replicas and CPU utilization targets.
