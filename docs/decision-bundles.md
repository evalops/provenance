# DSSE Decision Bundles

Provenance emits DSSE-formatted envelopes for every governance evaluation so downstream systems can verify policy outcomes independently. This document explains the payload structure, signing process, and recommended verification steps.

## Envelope Structure

Decision bundles follow the [in-toto DSSE specification](https://github.com/in-toto/ietf-draft), using JSON as the payload type:

```json
{
  "payloadType": "application/provenance.decision+json",
  "payload": "<base64-encoded canonical JSON>",
  "payloadSha256": "<hex digest of the decoded payload>",
  "signatures": [
    {
      "keyid": "decision-key",
      "sig": "<base64-encoded Ed25519 signature>"
    }
  ]
}
```

The decoded payload contains the authoritative decision context:

```json
{
  "analysis_id": "an_abcd1234",
  "repo_id": "acme/shop",
  "pr_number": "77",
  "decided_at": "2024-06-07T19:11:42.483920Z",
  "outcome": "block",
  "policy_version": "2024-06-01",
  "rationale": "Critical findings detected.",
  "risk_summary": {
    "findings_total": 3,
    "findings_by_category": {"code_execution": 2, "secrets": 1},
    "findings_by_severity": {"critical": 1, "high": 2},
    "coverage": {
      "total_lines": 22,
      "attributed_lines": 18,
      "unknown_line_count": 4,
      "coverage_percent": 81.82
    }
  },
  "provenance_confidence": {
    "agent_attribution_percent": 95.0,
    "cryptographic_attestations": 17
  },
  "thresholds": {
    "warn": {"code_execution": 1},
    "block": {"secrets": 1}
  },
  "detector_capabilities": {
    "semgrep": {
      "ruleset": "app/detection_rules/semgrep_rules.yml",
      "sha256": "..."
    }
  },
  "line_count": 22,
  "finding_count": 3,
  "inputs_sha256": "e843a82d88e1416f33804ce96f41d2a57c99b35a2f1b9e1d4fb86a03d38f6c5d"
}
```

### Canonicalization

- The payload is serialized with `sort_keys=True` and compact separators `(",", ":")`.
- `payloadSha256` is computed over the raw UTF-8 bytes of this canonical JSON.
- Signatures cover the same byte sequence, ensuring tamper detection.

## Retrieving Bundles

- API: `GET /v1/analysis/{id}/bundle` returns the envelope alongside the original analysis identifier.
- Telemetry: a `decision_bundle` event is published to configured sinks (Redis, ClickHouse, Snowflake, etc.) for streaming ingestion.
- CI: the GitHub Action recipe in [docs/ci-integration.md](ci-integration.md) demonstrates downloading the bundle and archiving it as an artifact.

## Signature Verification

If `PROVENANCE_DECISION_SIGNING_KEY` is configured on the server, an Ed25519 signature is attached to each bundle. Clients verify signatures with the corresponding public key (`VerifyKey`).

Python example:

```python
import base64
import json
from nacl.signing import VerifyKey

def verify_bundle(envelope: dict, verify_key_b64: str) -> dict:
    payload_bytes = base64.b64decode(envelope["payload"])
    expected_sha = envelope["payloadSha256"]
    actual_sha = __import__("hashlib").sha256(payload_bytes).hexdigest()
    if actual_sha != expected_sha:
        raise ValueError("payloadSha256 mismatch")

    signatures = envelope.get("signatures") or []
    if not signatures:
        raise ValueError("no signatures present")

    verify_key = VerifyKey(base64.b64decode(verify_key_b64))
    signature = base64.b64decode(signatures[0]["sig"])
    verify_key.verify(payload_bytes, signature)
    return json.loads(payload_bytes)
```

Validation checklist:

- Compare `analysis_id`, `repo_id`, and `pr_number` against the workflow that fetched the bundle.
- Inspect `inputs_sha256` to confirm the provenance inputs used by governance match the expected diff metadata.
- Review `detector_capabilities` to confirm the rule packs and detectors loaded at evaluation time.

## Integrating with Sigstore / Rekor

- Push the envelope to an append-only transparency log to create an auditable trail of governance decisions.
- Optionally include the DSSE bundle as an annotation on OCI artifacts, release tags, or SBOM documents to tie provenance decisions to shipped assets.

## Troubleshooting

- Empty `signatures`: ensure `PROVENANCE_DECISION_SIGNING_KEY` is set to a base64-encoded Ed25519 private key on the server; restart the service after updating the setting.
- Hash mismatch: verify that intermediaries are not reformatting the JSON (e.g., pretty-printing the payload before storage). Always store the original envelope untouched.
- Out-of-sync detector metadata: confirm the analysis ingestion stage persisted detector capability snapshots (`AnalysisService` copies active detector digests into `provenance_inputs.detector_capabilities`).
