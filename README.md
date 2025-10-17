# Provenance & Risk Analytics

> Attribute every changed line to its authoring agent, evaluate risk with Semgrep, and deliver governance-grade analytics.

## Why This Exists

Modern teams mix human and AI-generated code. This service makes that blend observable:

- **Attribution** – Trace each changed line to the producing agent/session via provenance markers supplied at ingestion.
- **Detection** – Run Semgrep rule packs on the diff to flag risky patterns (SQLi, `eval`, etc.).
- **Analytics** – Produce KPIs such as agent-level risk rate, provenance coverage, volume/churn, and trend deltas.
- **Governance** – Expose policy decisions (allow/block/warn) with evidence that maps back to repos, PRs, files, and lines.


## Architecture In Brief

```
┌────────────────┐      ┌────────────────────┐      ┌────────────────────┐
│ Git Provider / │      │ Ingestion &         │      │ Governance Engine   │
│ CI Integrations│ ───▶ │ Attribution Engine  │ ───▶ │ (policy + evidence) │
└────────────────┘      └─────────┬──────────┘      └───────────┬────────┘
                                  │                             │
                                  ▼                             ▼
                          ┌────────────────┐         ┌────────────────────┐
                          │ Detection via  │         │ Warehouse &         │
                          │ Semgrep        │         │ Analytics (Redis)   │
                          └────────────────┘         └────────────────────┘
```

- **FastAPI** wires the ingestion (`/v1/analysis`), analytics, and governance APIs.
- **Redis** persists analyses, changed lines, findings, and decisions using sorted sets, lists, and hashes.
- **Semgrep** runs as the detection engine. Rules live in `app/detection_rules/semgrep_rules.yml`; extend or replace them to suit your policy.

## Quickstart

```bash
# 1. Install dependencies into a managed virtualenv
make setup

# 2. Ensure Redis is running (default: redis://localhost:6379/0)
#    You can override via PROVENANCE_REDIS_URL

# 3. Launch the API with hot reload
make run
```

Visit http://localhost:8000/docs for interactive OpenAPI documentation.

## Configuration

All settings can be driven by environment variables prefixed with `PROVENANCE_`.
Copy `.env.example` to `.env` and adjust values locally if you prefer dotenv-style configuration.

| Variable | Purpose | Default |
| --- | --- | --- |
| `PROVENANCE_SERVICE_BASE_URL` | Base URL used in status links | `http://localhost:8000` |
| `PROVENANCE_REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `PROVENANCE_PROVENANCE_BLOCK_ON_UNKNOWN` | Block when changed lines lack agent attribution | `false` |
| `PROVENANCE_RISK_HIGH_SEVERITY_THRESHOLD` | Number of high-severity findings before issuing a warn | `1` |
| `PROVENANCE_ANALYTICS_DEFAULT_WINDOW` | Default lookback window for analytics | `7d` |
| `PROVENANCE_SEMGREP_CONFIG_PATH` | Override path/URL for Semgrep configuration | *(bundled rules)* |
| `PROVENANCE_TIMESERIES_BACKEND` | Backend for analytics event export (`file`, `bigquery`, `snowflake`, `clickhouse`, `off`) | `file` |
| `PROVENANCE_TIMESERIES_PATH` | File path for JSONL events when using `file` backend | `data/timeseries_events.jsonl` |
| `PROVENANCE_TIMESERIES_PROJECT` | Cloud project/account for warehouse exports | *(unset)* |
| `PROVENANCE_TIMESERIES_DATABASE` | Warehouse database name (Snowflake only) | *(unset)* |
| `PROVENANCE_TIMESERIES_DATASET` | Dataset/schema for warehouse exports | *(unset)* |
| `PROVENANCE_TIMESERIES_TABLE` | Destination table for warehouse exports | *(unset)* |
| `PROVENANCE_TIMESERIES_CREDENTIALS_PATH` | Service account JSON for BigQuery (optional) | *(unset)* |
| `PROVENANCE_TIMESERIES_USER` | Warehouse service user (Snowflake) | *(unset)* |
| `PROVENANCE_TIMESERIES_PASSWORD` | Warehouse password/secret (Snowflake) | *(unset)* |
| `PROVENANCE_TIMESERIES_WAREHOUSE` | Snowflake warehouse to use | *(unset)* |
| `PROVENANCE_TIMESERIES_ROLE` | Snowflake role to assume | *(unset)* |
| `PROVENANCE_TIMESERIES_BATCH_SIZE` | Buffer size before flushing warehouse writes | `25` |
| `PROVENANCE_OTEL_ENABLED` | Enable OpenTelemetry metrics export | `false` |
| `PROVENANCE_OTEL_EXPORTER` | Metrics exporter target (`console`) | `console` |
| `PROVENANCE_OTEL_OTLP_ENDPOINT` | OTLP metrics endpoint (when exporter=`otlp`) | *(unset)* |
| `PROVENANCE_OTEL_PROMETHEUS_PORT` | Prometheus exporter port (when exporter=`prometheus`) | `9464` |
| `PROVENANCE_POLICY_WARN_THRESHOLDS` | JSON map of category warn thresholds | `{}` |
| `PROVENANCE_POLICY_BLOCK_THRESHOLDS` | JSON map of category block thresholds | `{}` |
| `PROVENANCE_DETECTOR_MODULE_PATHS` | JSON array of detector module paths to auto-load | `[]` |
| `PROVENANCE_GITHUB_TOKEN` | Personal access token for GitHub API enrichment | *(unset)* |
| `PROVENANCE_GITHUB_BASE_URL` | GitHub enterprise base URL (optional) | *(unset)* |
| `PROVENANCE_GITHUB_AGENT_LABEL_PREFIX` | PR label prefix used to infer agent IDs | `agent:` |
| `PROVENANCE_GITHUB_CACHE_TTL_SECONDS` | Cache TTL (seconds) for GitHub metadata lookups | `300` |
| `PROVENANCE_GITHUB_AGENT_MAP` | JSON map of GitHub logins/keywords to agent IDs | `{}` |
| `PROVENANCE_GITHUB_REVIEWER_TEAM_MAP` | JSON map of reviewer logins to team names for cohort reporting | `{}` |
| `PROVENANCE_TEAM_REVIEW_BUDGETS` | JSON map of team names to max expected human review counts per window | `{}` |
| `PROVENANCE_AGENT_PUBLIC_KEYS` | JSON map of agent IDs to base64 Ed25519 public keys for attestation verification | `{}` |
| `PROVENANCE_CLICKHOUSE_URL` | ClickHouse HTTP endpoint for analytics export (when backend=`clickhouse`) | *(unset)* |
| `PROVENANCE_CLICKHOUSE_DATABASE` | ClickHouse database name (optional if table already qualified) | `provenance` |
| `PROVENANCE_CLICKHOUSE_USER` | ClickHouse user for authenticated writes | *(unset)* |
| `PROVENANCE_CLICKHOUSE_PASSWORD` | ClickHouse password for authenticated writes | *(unset)* |

## Detection Pipeline

- Rules are bundled in `app/detection_rules/semgrep_rules.yml`.
- Override with your own rule pack by setting `PROVENANCE_SEMGREP_CONFIG_PATH` (file path, directory, or remote Semgrep registry URL).
- During analysis execution we materialize the changed lines to a temporary workspace and run:

  ```bash
  semgrep --config app/detection_rules/semgrep_rules.yml --json
  ```

- The JSON results are mapped back to the originating changed lines so findings retain repo/PR/file/line attribution.
- Extend the rule pack or point the detector at your organization-wide Semgrep registry by updating `SemgrepDetector` in `app/services/detection.py`.
- Register additional detectors by providing module paths in `PROVENANCE_DETECTOR_MODULE_PATHS`; each module should expose `register_detectors()` returning `BaseDetector` instances.
- Built-in heuristics include a Python import detector that flags risky modules (e.g., `subprocess`, `pickle`); extend this pattern with your own detectors via modular hooks.
- Introspect active detectors via `/v1/detectors/capabilities` to confirm bundled Semgrep packs, digests, and custom modules loaded at runtime.

## GitHub Provenance Enrichment

- When GitHub credentials are configured, the service inspects commit trailers, PR labels, review comments, reviewer identities/teams, and PR timelines to fill missing agent attribution (see `app/provenance/github_resolver.py`).
- The resolver persists review conversations (thread counts, team participation, bot override details, classification breakdowns, response latency), CI outcomes (time-to-green, failing check taxonomy), and commit/timeline summaries (force pushes, human follow-ups, rewrite loops) so analytics/governance can act without re-crawling GitHub.
- Governance automatically raises alerts when bot change requests are bypassed or force-pushes land after approval; `/v1/analytics/review-alerts` and `/v1/analytics/review-load` expose the same signals for monitoring.
- Agents can optionally attach Ed25519 signatures for each changed line. Supply public keys via `PROVENANCE_AGENT_PUBLIC_KEYS`; verified signatures boost provenance confidence and surface cryptographic evidence alongside heuristic attribution.

## API Surface

| Endpoint | Method | Description |
| --- | --- | --- |
| `/healthz` | `GET` | Liveness probe |
| `/v1/analysis` | `POST` | Submit a pull request (diff + provenance) for asynchronous analysis |
| `/v1/analysis/{id}` | `GET` | Poll analysis status, findings count, and risk summary snapshot |
| `/v1/analysis/{id}/decision` | `GET` | Fetch the governance decision (allow/block/warn) with evidence |
| `/v1/analysis/{id}/bundle` | `GET` | Retrieve the signed DSSE decision bundle |
| `/v1/analysis/{id}/sarif` | `GET` | Retrieve the SARIF 2.1.0 findings report for the analysis |
| `/v1/analytics/summary` | `GET` | Retrieve aggregated KPIs (risk rate, provenance, volume, churn, complexity, etc.) |
| `/v1/analytics/agents/behavior` | `GET` | Retrieve composite behavioral snapshots for each agent |
| `/v1/detectors/capabilities` | `GET` | Enumerate active detectors (Semgrep configs, versions, metadata) |
| `/metrics` | `GET` | Prometheus scrape endpoint (when exporter is `prometheus`) |

Example ingestion payload:

```json
{
  "repo": "acme/shop",
  "pr_number": "42",
  "base_sha": "abc123",
  "head_sha": "def456",
  "branch": "feature/checkout-hardening",
  "provenance_data": {
    "metadata": {
      "attestation_url": "https://evidence.example.com/claims/123"
    },
    "changed_lines": [
      {
        "file_path": "api/orders.py",
        "line_number": 128,
        "change_type": "added",
        "content": "query = f\"SELECT * FROM orders WHERE id = {order_id}\"",
        "language": "python",
        "attribution": {
          "agent_id": "claude-3-opus",
          "agent_session_id": "sess-789",
          "provenance_marker": "Agent-ID: claude-3-opus-20240229"
        }
      }
    ]
  }
}
```

## Agent Insights & Analytics

- `/v1/analytics/summary` now surfaces GitHub-aware metrics alongside the existing risk/volume suite: `code_volume`, `code_churn_rate`, `avg_line_complexity`, `agent_response_rate`, `agent_response_p50_hours`, `agent_response_p90_hours`, `reopened_threads`, `force_push_events`, `rewrite_loops`, `human_followup_commits`, `human_followup_fast`, `ci_time_to_green_hours`, `ci_failed_checks`, `agent_commit_ratio`, `commit_lead_time_hours`, `force_push_after_approval`, `human_reviewer_count`, `avg_human_reviewers`, `avg_unique_reviewers`, `bot_review_events`, `bot_block_events`, `bot_block_overrides`, `bot_block_resolved`, `bot_reviewer_count`, `bot_informational_only_reviewer_count`, `bot_comment_count`, and `classification_<label>_count` (e.g., `classification_security_count`).
- `/v1/analytics/agents/behavior` returns composite snapshots that now blend code/finding metrics with review conversation health (thread counts, response latency, classification breakdowns), CI friction (failures, time-to-green), commit dynamics (force pushes, rewrite loops, human follow-ups), and attention heatmaps (top paths + hot files) per agent.
- Snapshots also include reviewer cohort context (`human_reviewer_count`, association breakdowns), bot review behavior (`bot_block_events`, `bot_block_overrides`), provenance anomalies (`force_push_after_approval_count`), and CI failure taxonomy (failing check names and contexts) to highlight operational hotspots.
- `/v1/analytics/review-alerts` highlights agents/analyses where bot change-requests were overridden or force-pushes occurred post-approval.
- `/v1/analytics/review-load` reports human vs. bot review load per agent, while `/v1/analytics/review-load/teams` aggregates human reviewer effort by the configured team map.
- Review-focused metrics (`review_comments`, `unique_reviewers`, `review_events`, `agent_comment_mentions`) continue to leverage GitHub PR data when credentials are supplied; classification metrics reflect the resolver's heuristic labeling of each conversation snippet.
- Use `PROVENANCE_ANALYTICS_DEFAULT_WINDOW` or query parameters such as `?time_window=14d` to track longer horizons and compare agents.

### Dry-Running the GitHub Resolver

To smoke-test the GitHub resolver end-to-end:

1. Export `PROVENANCE_GITHUB_TOKEN` with repo-scoped access.
2. Create a throwaway branch and open a PR against `main`; include a commit trailer such as `Agent-ID: test-agent`.
3. POST a synthetic analysis payload pointing at that PR (`repo`, `pr_number`, `head_sha`) so the resolver can hydrate metadata.
4. Inspect the resulting `analysis` record and `/v1/analytics/summary` output to confirm review/CI signals flowed through.

The same process works against forks or sandboxes—helpful when validating new heuristics without polluting production repositories.

## CI Integration

- A composite GitHub Action is bundled at `clients/github-action/`. Reference it from `.github/workflows/provenance.yml` and pass `api_url` + `api_token` secrets to submit each pull request diff. The action fails automatically when the governance outcome is `block`.
- The workflow helper collects the PR diff (`base_sha..head_sha`), submits it to `/v1/analysis`, polls `/v1/analysis/{id}`, and prints the enriched decision payload so reviewers can inspect risk summaries inline.
- Consume `/v1/analysis/{id}/sarif` when you need static-analysis interoperability (e.g., uploading to GitHub code scanning or aggregating findings in other dashboards).
- Surface decision bundles in CI by hitting `/v1/analysis/{id}/bundle` (e.g., attach the DSSE envelope as a build artifact) to preserve signed provenance for downstream policy checks.
- See [docs/ci-integration.md](docs/ci-integration.md) for a comprehensive workflow guide, SARIF upload recipe, artifact archiving, and non-GitHub CI examples.

## Telemetry Export

- Each analysis generates an `analysis_metrics` event written to `data/timeseries_events.jsonl` by default.
- Switch `PROVENANCE_TIMESERIES_BACKEND` to `bigquery` or `snowflake` and provide the project/database/dataset/table knobs to buffer events for warehouse loaders.
- Point the backend to `off` to disable exports entirely.
- Install warehouse dependencies when needed: `uv sync --group warehouse` (installs `snowflake-connector-python`).
- Install observability exporters via `uv sync --group observability` when enabling OTLP (install `opentelemetry-exporter-otlp`). For Prometheus support, install `opentelemetry-exporter-prometheus` manually.
- Set `PROVENANCE_OTEL_ENABLED=true` to emit OpenTelemetry metrics (currently using the console exporter by default).
- Event payloads include per-agent code volume, churn rates, complexity heuristics, and counts by finding category/severity.

### ClickHouse quickstart

- Run `make clickhouse-up` to launch a local ClickHouse instance with the starter schema from `infrastructure/clickhouse/schema.sql`.
- Configure `PROVENANCE_TIMESERIES_BACKEND=clickhouse`, `PROVENANCE_CLICKHOUSE_URL=http://localhost:8123`, and `PROVENANCE_TIMESERIES_TABLE=analysis_events` (or point at your own table) to mirror analytics events into ClickHouse.
- Downstream jobs can query the `provenance` database (tables: `analysis_events`, `findings`, `review_events`) for long-horizon reporting while Redis continues to serve hot state.

## Dashboard

- Install dashboard dependencies: `uv sync --group dashboard`
- Launch Streamlit UI: `uv run --group dashboard -- streamlit run dashboards/agent_dashboard.py`
- Set `PROVENANCE_DASHBOARD_API` to point at your deployed API when running remotely.
- To enable trend charts, set `PROVENANCE_DASHBOARD_EVENTS` to a path containing the exported JSONL events (defaults to `data/timeseries_events.jsonl`).
- If the Prometheus exporter is enabled (`PROVENANCE_OTEL_EXPORTER=prometheus`), scrape metrics from `/metrics`.

## SDK & Schema

- Generate an OpenAPI schema with `make docs` (writes `openapi.json`).
- A lightweight synchronous client lives in `clients/python`; use `ProvenanceClient` for basic ingestion/status/analytics calls.
- Async support is available via `AsyncProvenanceClient`. Install the client SDK with `pip install provenance[client]` and import from `clients.python`.

## Additional Documentation

- [CI Integration Guide](docs/ci-integration.md) – Configure GitHub Actions, upload SARIF, archive decision bundles, and adapt the workflow to other CI systems.
- [Governance & Risk Model](docs/governance-and-risk-model.md) – Understand decision flow, thresholds, and tuning guidance.
- [Configuration Reference](docs/configuration.md) – Environment variables grouped by subsystem with defaults and usage tips.
- [Detector Authoring Guide](docs/detector-authoring.md) – Build custom detectors, register modules, and manage rule packs.
- [SARIF Reporting](docs/sarif-reporting.md) – Understand the SARIF 2.1.0 output, severity mapping, and customization hooks.
- [DSSE Decision Bundles](docs/dsse-decision-bundles.md) – Inspect the envelope schema, verify signatures, and integrate with transparency logs.

## Data Persistence Model

- **Analyses** – Stored as JSON blobs keyed by `analysis:{analysis_id}` with a sorted set index for time-window queries.
- **Changed Lines** – Backed by Redis lists (`analysis:{id}:lines`) to retain insertion order and provenance data.
- **Findings** – Redis hashes per analysis hold Semgrep findings for quick lookup.
- **Decisions** – Single JSON document per analysis storing policy outcome and evidence.

## Development Workflow

```bash
# Static checks (Python bytecode compilation)
make compile

# Run the test suite (uses fakeredis for analytics tests)
make test
```

## Containerisation

Use the provided Dockerfile to build and run the API locally:

```bash
docker build -t provenance-api .
docker run --rm -p 8000:8000 provenance-api
```

Or bring up the service plus Redis via docker compose:

```bash
docker compose up --build
```

The API will be available at http://localhost:8000 with Prometheus metrics (if enabled) exposed at `/metrics`.

## Next Steps / TODO

- Wire Semgrep to enterprise rule registries or rule bundles.
- Stream analysis events to your data warehouse instead of relying solely on Redis.
- Enrich analytics endpoints with MTTR, suppression rates, and trend deltas.
