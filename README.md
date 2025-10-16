# Agent Code Provenance & Risk Analytics

> Attribute every changed line to its authoring agent, evaluate risk with Semgrep, and deliver governance-grade analytics.

## Why This Exists

Modern teams mix human and AI-generated code. This service makes that blend observable:

- **Attribution** – Trace each changed line to the producing agent/session via provenance markers supplied at ingestion.
- **Detection** – Run Semgrep rule packs on the diff to flag risky patterns (SQLi, `eval`, etc.).
- **Analytics** – Produce KPIs such as agent-level risk rate, provenance coverage, and trend deltas.
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
| `/v1/analytics/summary` | `GET` | Retrieve aggregated KPIs (risk rate, provenance coverage, etc.) |

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
