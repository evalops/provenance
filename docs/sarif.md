# SARIF Reporting

Provenance exposes a SARIF 2.1.0 output so findings can flow into platforms that understand static-analysis results (GitHub code scanning, Azure DevOps, VS Code, etc.). This document explains how the report is constructed and how to tailor it for your organization.

## Endpoint

- `GET /v1/analysis/{id}/sarif` returns the SARIF payload for a completed analysis.
- The response is cached in Redis alongside findings, so the call is inexpensive and idempotent.
- Requests return `404` while an analysis is still running or if the identifier is unknown.

Example:

```bash
curl -sSf -H "Authorization: Bearer ${PROVENANCE_API_TOKEN}" \
  "${PROVENANCE_API_URL}/v1/analysis/an_123/sarif" \
  -o provenance.sarif
```

## Structure

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Provenance Governance",
          "informationUri": "https://github.com/evalops/provenance",
          "rules": []
        }
      },
      "invocations": [
        {
          "executionSuccessful": true,
          "startTimeUtc": "2024-06-07T18:02:19.103Z",
          "endTimeUtc": "2024-06-07T18:02:22.481Z"
        }
      ],
      "results": [
        {
          "ruleId": "semgrep.code_execution.eval",
          "level": "error",
          "message": {"text": "Avoid eval on untrusted input."},
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {"uri": "services/orders.py"},
                "region": {"startLine": 10}
              }
            }
          ],
          "properties": {
            "analysis_id": "an_123",
            "repo_id": "acme/shop",
            "pr_number": "77",
            "engine_name": "semgrep"
          }
        }
      ]
    }
  ]
}
```

### Severity Mapping

| Provenance Severity | SARIF Level |
| --- | --- |
| `critical`, `high` | `error` |
| `medium` | `warning` |
| `low` | `note` |

If a finding's severity is unknown, the default level is `warning`.

### Custom Rules Metadata

The `tool.driver.rules` array is currently empty. To include rich rule metadata (descriptions, help URIs, guidance), extend `app/services/sarif.py` to build a rule lookup keyed by `ruleId` and populate:

```python
{
    "id": finding.rule_key,
    "name": finding.rule_display_name,
    "shortDescription": {"text": finding.message},
    "helpUri": "https://internal.docs/rules/...",
}
```

## Common Integrations

- **GitHub code scanning:** Use [`github/codeql-action/upload-sarif`](https://github.com/github/codeql-action) to publish findings to the Security tab. See [docs/ci-integration.md](ci-integration.md) for a workflow example.
- **Azure DevOps:** Attach the SARIF file to the build summary or upload it through the [SARIF Slicer extension](https://marketplace.visualstudio.com/items?itemName=sariftools.sarif-tools).
- **IDE plugins:** Many editors (VS Code, JetBrains) consume SARIF files directly; download them as part of a local audit or pre-commit hook to surface findings inline.

## Tailoring the Output

- Override the tool name/information URI by editing `app/services/sarif.py`. For multi-detector deployments, consider annotating the driver with the active ruleset or detector pack digest.
- Add `partialFingerprints` to `results` if you want GitHub to de-duplicate findings across subsequent runs (e.g., derive a hash from `ruleId`, `file_path`, `line_number`).
- Enrich `properties` with internal routing metadata: team ownership, risk score, remediation SLA, etc. Downstream automation can then triage findings without rehydrating the decision bundle.

## Troubleshooting

- Empty `runs`: confirm that findings are stored in Redis (`list_findings` should return entries). Analyses with zero findings intentionally return an empty `results` array.
- Missing files: ensure the ingestion payload records the correct relative paths. SARIF uses the `uri` verbatim, so provide repo-root relative paths for best compatibility.
- Upload failures in GitHub: validate the SARIF against the schema (`npx @microsoft/sarif-multitool validate provenance.sarif`).
