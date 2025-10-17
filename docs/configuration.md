# Configuration Reference

The service is configured via environment variables (with `uvicorn` expecting uppercase snake-case). This reference groups related settings, documents defaults, and explains how they influence behaviour.

## Core Service

| Variable | Default | Description |
| --- | --- | --- |
| `PROVENANCE_SERVICE_HOST` | `0.0.0.0` | Bind address for the API server. |
| `PROVENANCE_SERVICE_PORT` | `8000` | HTTP port for FastAPI. |
| `PROVENANCE_SERVICE_BASE_URL` | `http://localhost:8000` | External URL used when generating links in API responses. |
| `PROVENANCE_API_V1_PREFIX` | `/v1` | Prefix applied to API routes. |
| `PROVENANCE_API_TOKEN` | unset | Shared secret for simple token auth on ingestion endpoints. Use a stronger mechanism (e.g., OAuth) in production. |

## Data Stores

| Variable | Default | Description |
| --- | --- | --- |
| `PROVENANCE_REDIS_URL` | `redis://localhost:6379/0` | Primary datastore for analyses, findings, and decisions. |
| `PROVENANCE_REDIS_PASSWORD` | unset | Password for secured Redis deployments. |
| `PROVENANCE_TIMESERIES_BACKEND` | `file` | Destination for analytics events: `file`, `clickhouse`, `snowflake`, `bigquery`, or `off`. |
| `PROVENANCE_TIMESERIES_PATH` | `data/timeseries_events.jsonl` | File path used when backend is `file`. |
| `PROVENANCE_CLICKHOUSE_URL` | unset | HTTP endpoint for ClickHouse when selected as backend. |
| `PROVENANCE_SNOWFLAKE_ACCOUNT` | unset | Snowflake account identifier (when backend is `snowflake`). |
| `PROVENANCE_BIGQUERY_DATASET` | unset | Dataset name for BigQuery backend. |

## Governance & Risk

See [Governance & Risk Model](governance-and-risk-model.md) for detailed context.

| Variable | Default | Description |
| --- | --- | --- |
| `PROVENANCE_BLOCK_ON_UNKNOWN` | `false` | Block analyses with unattributed lines. |
| `PROVENANCE_RISK_HIGH_SEVERITY_THRESHOLD` | `1` | Warn threshold for high severity findings. |
| `PROVENANCE_POLICY_WARN_THRESHOLDS` | `{}` | JSON mapping of category → warn threshold. |
| `PROVENANCE_POLICY_BLOCK_THRESHOLDS` | `{}` | JSON mapping of category → block threshold. |
| `PROVENANCE_DEFAULT_POLICY_VERSION` | `2024-06-01` | Version string embedded in decisions. |
| `PROVENANCE_DECISION_SIGNING_KEY` | unset | Base64 Ed25519 private key for DSSE signing. |
| `PROVENANCE_DECISION_KEY_ID` | `"decision-key"` | Label for the signing key. |

## Detectors & Provenance

| Variable | Default | Description |
| --- | --- | --- |
| `PROVENANCE_DETECTOR_MODULE_PATHS` | unset | Comma-separated list of Python modules that register additional detectors. |
| `PROVENANCE_SEMGREP_RULES_PATH` | `app/detection_rules/semgrep_rules.yml` | Default Semgrep ruleset used by the built-in detector. |
| `PROVENANCE_AGENT_PUBLIC_KEYS` | `{}` | Mapping of agent IDs to Ed25519 public keys (JSON). Enables cryptographic attribution of changed lines. |
| `PROVENANCE_PROVENANCE_MARKERS` | `{}` | Optional hints for matching agent markers in commit messages. |

## GitHub Integration

| Variable | Default | Description |
| --- | --- | --- |
| `PROVENANCE_GITHUB_TOKEN` | unset | Personal access token or GitHub App installation token for enrichment. |
| `PROVENANCE_GITHUB_APP_ID` | unset | GitHub App identifier (when using app-based auth). |
| `PROVENANCE_GITHUB_APP_PRIVATE_KEY` | unset | Base64 encoded private key for the GitHub App. |
| `PROVENANCE_GITHUB_WEBHOOK_SECRET` | unset | Shared secret for webhook verification if you extend the service to receive GitHub events. |

## Observability

| Variable | Default | Description |
| --- | --- | --- |
| `PROVENANCE_OTEL_ENABLED` | `false` | Enable OpenTelemetry metrics/exporters. |
| `PROVENANCE_OTEL_EXPORTER` | `console` | Exporter target (`console`, `prometheus`, etc.). Additional dependencies might be required. |
| `PROVENANCE_OTEL_ENDPOINT` | unset | Collector endpoint for OTLP exporters. |
| `PROVENANCE_PROMETHEUS_PORT` | `9000` | Port to expose Prometheus metrics when exporter is `prometheus`. |

## Analytics Windows & Defaults

| Variable | Default | Description |
| --- | --- | --- |
| `PROVENANCE_ANALYTICS_DEFAULT_WINDOW` | `7d` | Default rolling window for analytics endpoints. |
| `PROVENANCE_ANALYTICS_DEFAULT_METRIC` | `code_volume` | Fallback metric when none provided. |

## CI / GitHub Action

| Variable | Default | Description |
| --- | --- | --- |
| `PROVENANCE_WRITE_RESPONSE_PATH` | unset | When set in CI, the GitHub Action writes the decision payload to this path for downstream steps. |
| `PROVENANCE_TRACE` | `0` | Enable verbose logging from the composite action’s HTTP client. |

## Secrets Handling Tips

- Store sensitive values (API tokens, signing keys) in secret managers or CI secrets, not in plaintext environment files.
- When using JSON-based settings (e.g., threshold mappings), prefer compact JSON strings: `{"secrets":1,"code_execution":2}` to avoid parsing surprises.
- Mount configuration files via Kubernetes secrets or Docker Compose `.env` files; the app uses `pydantic` settings, so environment variables are automatically parsed.
