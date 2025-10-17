# CI Integration Guide

This guide walks through wiring Provenance into continuous integration systems so every pull request is analyzed, decisions are enforced automatically, and evidence is archived for future audits.

## Prerequisites

- Provenance API endpoint (e.g. `https://provenance.example.com`).
- API token with permission to create analyses and read decisions.
- Python 3.12 runtime available to the pipeline (the bundled GitHub Action installs [uv](https://docs.astral.sh/uv/latest/) and reuses this repository's dependency lockfile).
- Optional: Ed25519 public key published via `PROVENANCE_DECISION_VERIFY_KEY` if your governance service signs DSSE bundles.

## GitHub Actions

We ship a composite action in `clients/github-action/` that:

1. Collects the unified diff between the PR base and head commits.
2. Submits the diff plus provenance metadata to `/v1/analysis`.
3. Polls `/v1/analysis/{id}` until the analysis completes.
4. Prints the structured decision payload for reviewer visibility.
5. Exits with a non-zero status when the policy outcome is `block`.

### Example Workflow

Save the following as `.github/workflows/provenance.yml` and provide the API configuration through GitHub secrets:

```yaml
name: Provenance Governance

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          # Ensure the full history is present for an accurate diff.
          fetch-depth: 0

      - name: Run Provenance analysis
        uses: ./clients/github-action
        with:
          api_url: ${{ secrets.PROVENANCE_API_URL }}
          api_token: ${{ secrets.PROVENANCE_API_TOKEN }}
```

When a decision is `block`, the job fails and the PR is marked red. `allow` and `warn` outcomes complete successfully; governance context is still attached to the run log for reviewer triage.

### Exposing SARIF Findings in GitHub

The analysis API now exposes a SARIF 2.1.0 representation of each run. Add a follow-up step to fetch the SARIF payload and upload it to the GitHub code scanning UI:

```yaml
      - name: Download SARIF report
        if: success() || failure()
        run: |
          set -euo pipefail
          ANALYSIS_ID=$(jq -r '.analysis_id' provenance.json)
          curl -sSf -H "Authorization: Bearer ${{ secrets.PROVENANCE_API_TOKEN }}" \
            "$${{ secrets.PROVENANCE_API_URL }}/v1/analysis/${ANALYSIS_ID}/sarif" \
            -o provenance.sarif

      - name: Upload SARIF to GitHub
        if: success() || failure()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: provenance.sarif
```

To make the SARIF payload available, update the action invocation to persist the API response JSON:

```yaml
      - name: Run Provenance analysis
        uses: ./clients/github-action
        with:
          api_url: ${{ secrets.PROVENANCE_API_URL }}
          api_token: ${{ secrets.PROVENANCE_API_TOKEN }}
        env:
          PROVENANCE_WRITE_RESPONSE_PATH: provenance.json
```

The `clients/github-action/run.py` script respects `PROVENANCE_WRITE_RESPONSE_PATH` and mirrors the latest decision payload to disk so downstream steps can reference the analysis identifier without re-polling the API.

### Archiving DSSE Decision Bundles

Signed DSSE envelopes provide tamper-evident evidence for pipeline attestations. Attach the bundle to the workflow artifacts:

```yaml
      - name: Archive decision bundle
        if: success() || failure()
        run: |
          set -euo pipefail
          ANALYSIS_ID=$(jq -r '.analysis_id' provenance.json)
          curl -sSf -H "Authorization: Bearer ${{ secrets.PROVENANCE_API_TOKEN }}" \
            "$${{ secrets.PROVENANCE_API_URL }}/v1/analysis/${ANALYSIS_ID}/bundle" \
            -o decision-bundle.json

      - uses: actions/upload-artifact@v4
        if: success() || failure()
        with:
          name: provenance-decision-bundle
          path: decision-bundle.json
          retention-days: 30
```

Auditors can later verify the payload hash and (if configured) Ed25519 signature against the published governance verification key.

## Other CI Systems

The workflow runner is a thin wrapper around four HTTP calls, so porting the integration to other CI providers is straightforward.

1. Generate the diff for the change under review. For example, in Jenkins:

   ```bash
   git fetch origin "${CHANGE_TARGET}"
   git diff --unified=0 "origin/${CHANGE_TARGET}...${GIT_COMMIT}" > diff.patch
   ```

2. Convert the diff to the `changed_lines` payload expected by `/v1/analysis`. You can reuse `clients/github-action/run.py` directly (`python -m clients.github-action.run ...`) or craft JSON with a custom script.

3. Submit the payload:

   ```bash
   curl -sSf -H "Authorization: Bearer ${PROVENANCE_API_TOKEN}" \
     -H "Content-Type: application/json" \
     -d "@payload.json" \
     "${PROVENANCE_API_URL}/v1/analysis"
   ```

4. Poll `/v1/analysis/{id}` until `status` is `completed`; enforce `decision.outcome == "block"` to fail the job.

5. Optionally fetch `/v1/analysis/{id}/sarif` and `/v1/analysis/{id}/bundle` to integrate with downstream scanners or evidence stores.

### Containerized Stages

If your CI stages run in disposable containers:

- Install `uv` (or `pip`) to execute `clients/github-action/run.py`.
- Mount the repository workspace so the diff generator can inspect tracked files.
- Provide `PROVENANCE_API_URL` and `PROVENANCE_API_TOKEN` via environment variables or secrets injection.
- Persist the JSON response to disk if later stages depend on the analysis identifier.

## Debugging Tips

- The composite action logs the raw decision payload; review the `risk_summary` and `decision.rationale` fields when a run blocks unexpectedly.
- Use the `PROVENANCE_TRACE=1` environment variable to enable verbose HTTP logging inside the action script.
- When testing locally, run `uv run clients/github-action/run.py --help` to see available arguments.
- Double-check that `fetch-depth: 0` (or an equivalent full clone) is configured; shallow clones omit base commits, leading to empty diffs and analyses that no-op.
- If polling times out, inspect the Provenance server logs for long-running detectors or governance evaluations; consider extending the `--timeout-s` flag in the CLI.
