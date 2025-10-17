# API Cookbook

This cookbook provides practical examples for interacting with the Provenance API—submitting analyses, polling decisions, retrieving evidence, and querying analytics.

## Authentication

All examples assume bearer token authentication:

```bash
export PROVENANCE_API_URL="https://provenance.example.com"
export PROVENANCE_API_TOKEN="your-api-token"
```

Headers:

```bash
-H "Authorization: Bearer ${PROVENANCE_API_TOKEN}"
```

## Submit an Analysis

### cURL

```bash
cat <<'JSON' > payload.json
{
  "repo": "acme/shop",
  "pr_number": "77",
  "base_sha": "abc123",
  "head_sha": "def456",
  "branch": "feature/harden",
  "provenance_data": {
    "metadata": {
      "attestation_url": "https://evidence.example.com/claims/123"
    },
    "changed_lines": [
      {
        "file_path": "services/orders.py",
        "line_number": 10,
        "change_type": "added",
        "language": "python",
        "content": "result = eval(user_input)",
        "attribution": {
          "agent_id": "github-copilot",
          "agent_session_id": "sess-1"
        }
      }
    ]
  }
}
JSON

curl -sSf \
  -H "Authorization: Bearer ${PROVENANCE_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @payload.json \
  "${PROVENANCE_API_URL}/v1/analysis"
```

Response:

```json
{
  "analysis_id": "an_b83b21d984f34c8f9abc0f2c82d4b79d",
  "status": "pending",
  "status_url": "https://provenance.example.com/v1/analysis/an_b83b21d984f34c8f9abc0f2c82d4b79d"
}
```

### Python (httpx)

```python
import httpx

client = httpx.Client(base_url="https://provenance.example.com", headers={
    "Authorization": f"Bearer {TOKEN}",
})

resp = client.post(
    "/v1/analysis",
    json={...}  # same payload as above
)
resp.raise_for_status()
analysis_id = resp.json()["analysis_id"]
```

## Poll Analysis Status

```bash
ANALYSIS_ID="an_b83b21d984f34c8f9abc0f2c82d4b79d"

curl -sSf \
  -H "Authorization: Bearer ${PROVENANCE_API_TOKEN}" \
  "${PROVENANCE_API_URL}/v1/analysis/${ANALYSIS_ID}"
```

Key fields:

- `status`: `pending`, `running`, `completed`, or `failed`.
- `findings_total`: Number of findings recorded.
- `risk_summary`: Aggregated findings and coverage.
- `decision`: Serialized policy decision (`outcome`, `rationale`, etc.).

## Fetch Governance Decision Evidence

```bash
curl -sSf \
  -H "Authorization: Bearer ${PROVENANCE_API_TOKEN}" \
  "${PROVENANCE_API_URL}/v1/analysis/${ANALYSIS_ID}/decision"
```

Use this if you need a pure decision payload (without the surrounding status data).

## Download DSSE Decision Bundle

```bash
curl -sSf \
  -H "Authorization: Bearer ${PROVENANCE_API_TOKEN}" \
  "${PROVENANCE_API_URL}/v1/analysis/${ANALYSIS_ID}/bundle" \
  -o decision-bundle.json
```

Verify the signature with the public key (see [DSSE Decision Bundles](dsse-decision-bundles.md)).

## Retrieve SARIF Report

```bash
curl -sSf \
  -H "Authorization: Bearer ${PROVENANCE_API_TOKEN}" \
  "${PROVENANCE_API_URL}/v1/analysis/${ANALYSIS_ID}/sarif" \
  -o provenance.sarif
```

Upload the SARIF to GitHub or other scanners using the workflow in the [CI Integration Guide](ci-integration.md).

## Query Analytics Summary

```bash
curl -sSf \
  -H "Authorization: Bearer ${PROVENANCE_API_TOKEN}" \
  "${PROVENANCE_API_URL}/v1/analytics/summary?metric=code_volume&time_window=7d"
```

Response snippet:

```json
{
  "result": {
    "metric": "code_volume",
    "data": [
      {"agent_id": "github-copilot", "value": 12.0},
      {"agent_id": "claude-3-opus", "value": 4.0}
    ]
  }
}
```

## Python Client Snippets

Use the bundled client (`clients/python`):

```python
from clients.python import ProvenanceClient

client = ProvenanceClient(
    base_url="https://provenance.example.com",
    api_token=TOKEN,
)

analysis = client.submit_analysis(payload)
decision = client.wait_for_decision(analysis.analysis_id, timeout_s=300)
bundle = client.get_decision_bundle(analysis.analysis_id)
sarif = client.get_sarif(analysis.analysis_id)
```

## Error Handling Tips

- **401 Unauthorized** – Check token validity and that the header is passed correctly.
- **404 Not Found** – Analysis ID is unknown or still processing (bundle/SARIF endpoints return 404 until `completed`).
- **429 Too Many Requests** – Implement exponential backoff when polling status.
- **5xx Errors** – Inspect server logs; detectors may have crashed or external services (Redis, ClickHouse) might be unavailable.

## Sample Script

`clients/github-action/run.py` contains a ready-made CLI for CI. You can run it locally:

```bash
uv run -- python clients/github-action/run.py \
  --api-url "${PROVENANCE_API_URL}" \
  --api-token "${PROVENANCE_API_TOKEN}" \
  --repo "acme/shop" \
  --pr "77" \
  --head-sha "$(git rev-parse HEAD)" \
  --base-sha "$(git merge-base HEAD origin/main)"
```

This script drives the same endpoints showcased above and serves as a reference for bespoke integrations.
