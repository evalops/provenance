# Agent Code Provenance & Risk Analytics

> Attribute every changed line to its authoring agent, evaluate risk with Semgrep, and deliver governance-grade analytics.

## Why This Exists

Modern teams mix human and AI-generated code. This service makes that blend observable:

- **Attribution** – Trace each changed line to the producing agent/session via provenance markers supplied at ingestion.
- **Detection** – Run Semgrep rule packs on the diff to flag risky patterns (SQLi, `eval`, etc.).
- **Analytics** – Produce KPIs such as agent-level risk rate, provenance coverage, volume/churn, and trend deltas.
- **Governance** – Expose policy decisions (allow/block/warn) with evidence that maps back to repos, PRs, files, and lines.

The codebase adheres to the requirements in `Agent Code Provenance & Risk Analytics service` specification.

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
uv sync

# 2. Ensure Redis is running (default: redis://localhost:6379/0)
#    You can override via PROVENANCE_REDIS_URL

# 3. Launch the API with hot reload
uv run -- uvicorn app.main:app --reload
```

Visit http://localhost:8000/docs for interactive OpenAPI documentation.

## Configuration

All settings can be driven by environment variables prefixed with `PROVENANCE_`.

| Variable | Purpose | Default |
| --- | --- | --- |
| `PROVENANCE_SERVICE_BASE_URL` | Base URL used in status links | `http://localhost:8000` |
| `PROVENANCE_REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `PROVENANCE_PROVENANCE_BLOCK_ON_UNKNOWN` | Block when changed lines lack agent attribution | `false` |
| `PROVENANCE_RISK_HIGH_SEVERITY_THRESHOLD` | Number of high-severity findings before issuing a warn | `1` |
| `PROVENANCE_ANALYTICS_DEFAULT_WINDOW` | Default lookback window for analytics | `7d` |
| `PROVENANCE_SEMGREP_CONFIG_PATH` | Override path/URL for Semgrep configuration | *(bundled rules)* |
| `PROVENANCE_TIMESERIES_BACKEND` | Backend for analytics event export (`file`, `bigquery`, `snowflake`, `off`) | `file` |
| `PROVENANCE_TIMESERIES_PATH` | File path for JSONL events when using `file` backend | `data/timeseries_events.jsonl` |
| `PROVENANCE_TIMESERIES_PROJECT` | Cloud project/account for warehouse exports | *(unset)* |
| `PROVENANCE_TIMESERIES_DATABASE` | Warehouse database name (Snowflake only) | *(unset)* |
| `PROVENANCE_TIMESERIES_DATASET` | Dataset/schema for warehouse exports | *(unset)* |
| `PROVENANCE_TIMESERIES_TABLE` | Destination table for warehouse exports | *(unset)* |
| `PROVENANCE_TIMESERIES_USER` | Warehouse service user (Snowflake) | *(unset)* |
| `PROVENANCE_TIMESERIES_PASSWORD` | Warehouse password/secret (Snowflake) | *(unset)* |
| `PROVENANCE_TIMESERIES_WAREHOUSE` | Snowflake warehouse to use | *(unset)* |
| `PROVENANCE_TIMESERIES_ROLE` | Snowflake role to assume | *(unset)* |

## Detection with Semgrep

- Rules are bundled in `app/detection_rules/semgrep_rules.yml`.
- Override with your own rule pack by setting `PROVENANCE_SEMGREP_CONFIG_PATH` (file path, directory, or remote Semgrep registry URL).
- During analysis execution we materialize the changed lines to a temporary workspace and run:

  ```bash
  semgrep --config app/detection_rules/semgrep_rules.yml --json
  ```

- The JSON results are mapped back to the originating changed lines so findings retain repo/PR/file/line attribution.
- Extend the rule pack or point the detector at your organization-wide Semgrep registry by updating `SemgrepDetector` in `app/services/detection.py`.

## API Surface

| Endpoint | Method | Description |
| --- | --- | --- |
| `/healthz` | `GET` | Liveness probe |
| `/v1/analysis` | `POST` | Submit a pull request (diff + provenance) for asynchronous analysis |
| `/v1/analysis/{id}` | `GET` | Poll analysis status, findings count, and risk summary snapshot |
| `/v1/analysis/{id}/decision` | `GET` | Fetch the governance decision (allow/block/warn) with evidence |
| `/v1/analytics/summary` | `GET` | Retrieve aggregated KPIs (risk rate, provenance, volume, churn, complexity, etc.) |
| `/v1/analytics/agents/behavior` | `GET` | Retrieve composite behavioral snapshots for each agent |

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

- `/v1/analytics/summary` now supports additional metrics: `code_volume`, `code_churn_rate`, and `avg_line_complexity` in addition to `risk_rate` and `provenance_coverage`.
- `/v1/analytics/agents/behavior` returns composite snapshots (volume, churn rate, heuristic complexity, and top vulnerability categories per agent) to power comparison dashboards.
- Use `PROVENANCE_ANALYTICS_DEFAULT_WINDOW` or query parameters such as `?time_window=14d` to track longer horizons and compare agents.

## Telemetry Export

- Each analysis generates an `analysis_metrics` event written to `data/timeseries_events.jsonl` by default.
- Switch `PROVENANCE_TIMESERIES_BACKEND` to `bigquery` or `snowflake` and provide the project/database/dataset/table knobs to buffer events for warehouse loaders.
- Point the backend to `off` to disable exports entirely.
- Install warehouse dependencies when needed: `uv sync --group warehouse` (installs `snowflake-connector-python`).
- Event payloads include per-agent code volume, churn rates, complexity heuristics, and counts by finding category/severity.

## Dashboard

- Install dashboard dependencies: `uv sync --group dashboard`
- Launch Streamlit UI: `uv run --group dashboard -- streamlit run dashboards/agent_dashboard.py`
- Set `PROVENANCE_DASHBOARD_API` to point at your deployed API when running remotely.
- To enable trend charts, set `PROVENANCE_DASHBOARD_EVENTS` to a path containing the exported JSONL events (defaults to `data/timeseries_events.jsonl`).

## Data Persistence Model

- **Analyses** – Stored as JSON blobs keyed by `analysis:{analysis_id}` with a sorted set index for time-window queries.
- **Changed Lines** – Backed by Redis lists (`analysis:{id}:lines`) to retain insertion order and provenance data.
- **Findings** – Redis hashes per analysis hold Semgrep findings for quick lookup.
- **Decisions** – Single JSON document per analysis storing policy outcome and evidence.

## Development Workflow

```bash
# Static checks (Python bytecode compilation)
uv run -- python -m compileall app

# Run the test suite (uses fakeredis for analytics tests)
uv run -- pytest
```

## Next Steps / TODO

- Wire Semgrep to enterprise rule registries or rule bundles.
- Stream analysis events to your data warehouse instead of relying solely on Redis.
- Enrich analytics endpoints with MTTR, suppression rates, and trend deltas.
