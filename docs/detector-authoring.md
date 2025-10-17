# Detector Authoring Guide

Provenance ships with a Semgrep-based detector and a few built-in heuristics. This guide explains how to add custom detectors, package rule packs, and test them locally.

## Detector Anatomy

Detectors inherit from `BaseDetector` (`app/services/detection.py`). Each detector implements:

- `detect(lines: list[ChangedLine]) -> list[Finding]`
- `capabilities() -> dict` (metadata describing rule packs, digests, etc.)

Detectors operate on the normalized `ChangedLine` models extracted from pull-request diffs, so they include file path, line number, language, attribution data, and more.

## Registering Detectors

Add your modules to `PROVENANCE_DETECTOR_MODULE_PATHS`. Each module must expose a `register_detectors()` function returning `BaseDetector` instances.

Example module (`my_detectors.py`):

```python
from app.services.detection import BaseDetector

class BanEvalDetector(BaseDetector):
    def detect(self, lines):
        findings = []
        for line in lines:
            if "eval(" in (line.content or ""):
                findings.append(
                    self.build_finding(
                        line=line,
                        rule_id="custom.eval.ban",
                        message="Avoid eval; it executes arbitrary code.",
                        category="code_execution",
                        severity="high",
                    )
                )
        return findings

    def capabilities(self):
        return {
            "rule_id": "custom.eval.ban",
            "description": "Flags eval usage in any language",
        }

def register_detectors() -> list[BaseDetector]:
    return [BanEvalDetector()]
```

Export the module path via environment variable:

```bash
export PROVENANCE_DETECTOR_MODULE_PATHS="my_detectors"
```

On startup, the detection service imports each module and registers the returned detectors.

## Semgrep Rule Packs

- Default rules live at `app/detection_rules/semgrep_rules.yml`.
- Replace or extend the pack by setting `PROVENANCE_SEMGREP_RULES_PATH` to a different file or directory (Semgrep understands directories and URLs).
- To depend on Semgrep-managed registries (`semgrep --config p/somepack`), mount the `.semgrep` auth config and update the detector initialization logic if additional authentication is needed.

### Adding Custom Rules

1. Write rules in YAML (either inline or separate files).
2. Run `semgrep --config app/detection_rules/semgrep_rules.yml --json` to preview findings.
3. Ensure rule IDs follow a namespaced convention (`org.package.rule`) to avoid collisions.
4. Document rules with `message`, `metadata`, and `severity` to enrich findings and SARIF output.

## Testing Detectors

- Unit tests: Add fixtures under `tests/test_detection.py` or create new suites to cover specific detectors. Use `ChangedLine` instances to simulate diffs.
- Integration tests: Extend `tests/test_api_endpoints.py` to submit payloads that exercise new rules and assert on findings and governance outcomes.
- Local runs: Use `scripts/provenance_client.py` (if available) or the GitHub Action script to submit a diff to a dev instance.

## Capabilities Endpoint

`GET /v1/detectors/capabilities` aggregates metadata from all registered detectors. Ensure `capabilities()` returns informative fields:

```python
return {
    "rule_id": "custom.eval.ban",
    "display_name": "Ban Eval in Python",
    "sha256": "<rule pack digest>",
    "config_path": "detectors/my_rules.yml",
    "last_updated": "2024-07-20T15:00:00Z",
}
```

This helps auditors confirm which rule packs were active during an analysis.

## Performance Considerations

- Detectors run synchronously today. For heavy workloads, consider batching queries or offloading to subprocesses.
- Avoid network calls during detection; enrichments should happen before ingestion or after governance to keep evaluation latency predictable.
- Use caching if rules require expensive initialization (e.g., loading ML models). Store the cache on the detector instance.
