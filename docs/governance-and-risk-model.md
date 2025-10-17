# Governance & Risk Model

This document explains how Provenance evaluates risk, determines allow/warn/block decisions, and which configuration knobs influence the outcome.

## Evaluation Flow

1. **Provenance Coverage** – Each changed line submitted with the analysis is examined for an agent attribution. Coverage metrics (total, attributed, unknown) inform enforcement when `PROVENANCE_BLOCK_ON_UNKNOWN=true`.
2. **Finding Aggregation** – Detectors produce findings with categories and severity levels. Governance summarizes totals, per-category counts, and severity buckets.
3. **Policy Thresholds** – Outcomes are derived by comparing summaries against configured thresholds and default heuristics.
4. **Review & Commit Signals** – When GitHub enrichment is enabled, governance inspects review overrides and force-push activity to adjust the outcome and emit alerts.
5. **Decision Bundling** – The final decision, risk summary, and inputs digest are wrapped in a DSSE envelope (optionally signed).

## Policy Outcomes

The decision pipeline evaluates conditions in priority order:

1. **Unknown Provenance** – If `PROVENANCE_BLOCK_ON_UNKNOWN=true` and any line lacks attribution, the outcome is `block` with rationale “Unknown agents detected…”.
2. **Critical Findings** – Any `critical` severity finding forces `block`.
3. **High Severity Threshold** – If `risk_high_severity_threshold` is reached (default: `1` high finding), the outcome falls to `warn`.
4. **Category Thresholds** – `PROVENANCE_POLICY_BLOCK_THRESHOLDS` and `PROVENANCE_POLICY_WARN_THRESHOLDS` map finding categories to numeric limits (e.g., `{"secrets": 1}`). When exceeded, outcomes escalate to `block` or `warn`.
5. **Review Overrides / Force Pushes** – GitHub metadata can escalate to `warn` or `block` if bot reviews were bypassed or force-pushes landed after approval.
6. **Default Allow** – If none of the above are triggered, the analysis is `allow`.

The rationale captures the first trigger encountered to keep explanations concise.

## Configuration Reference

| Setting | Default | Description |
| --- | --- | --- |
| `PROVENANCE_BLOCK_ON_UNKNOWN` | `false` | Block analyses when any changed line lacks agent attribution. |
| `PROVENANCE_RISK_HIGH_SEVERITY_THRESHOLD` | `1` | Number of `high` findings that trigger a `warn`. |
| `PROVENANCE_POLICY_WARN_THRESHOLDS` | `{}` | JSON mapping of finding category → warn threshold (inclusive). |
| `PROVENANCE_POLICY_BLOCK_THRESHOLDS` | `{}` | JSON mapping of finding category → block threshold (inclusive). |
| `PROVENANCE_DECISION_SIGNING_KEY` | unset | Base64 Ed25519 private key. Enables signing of DSSE bundles. |
| `PROVENANCE_DECISION_KEY_ID` | `"decision-key"` | Optional key identifier embedded in signature records. |
| `PROVENANCE_DEFAULT_POLICY_VERSION` | `2024-06-01` | Version stamp included in decisions for audit tracking. |

> The full environment variable list lives in [Configuration Reference](configuration.md). This table highlights the governance-specific controls.

## Risk Summary Schema

Every decision exports a `risk_summary` block:

```json
{
  "findings_total": 3,
  "findings_by_category": {"code_execution": 2, "secrets": 1},
  "findings_by_severity": {"high": 2, "critical": 1},
  "coverage": {
    "total_lines": 22,
    "attributed_lines": 18,
    "unknown_line_count": 4,
    "coverage_percent": 81.82
  },
  "bot_block_overrides": 1,
  "bot_block_resolved": 1,
  "force_push_after_approval": true
}
```

- `coverage` quantifies attribution confidence and feeds both alerting and DSSE payloads.
- Optional GitHub metadata fields (`bot_block_overrides`, etc.) appear when enrichment is enabled.

## Weighted Risk Score (Planned)

The roadmap includes a composite risk score that blends severity, coverage, and review heuristics. Upcoming changes will add:

- `risk_score` – Numeric index (0–100) aggregating weighted factors.
- `score_breakdown` – Component contributions (e.g., `{"coverage": 20, "severity": 50, "review": 10}`).
- Configurable weights via `PROVENANCE_RISK_WEIGHTS`.

Once implemented, governance decisions will still rely on hard thresholds for blocking, but the score will enrich analytics views and downstream automation.

## Tuning Guidance

1. **Start Conservative** – Block on critical findings, warn on high severity bursts, and observe review overrides before enforcing attribution coverage.
2. **Iterate on Categories** – Align category thresholds with detector packs (e.g., treat “secrets” differently from “lint”).
3. **Use DSSE Bundles** – Signatures provide a tamper-evident record of enforcement logic. Verify bundles in CI to ensure configuration drift doesn’t silently relax policies.
4. **Monitor Analytics** – `/v1/analytics/summary` and `/v1/analytics/agents/behavior` reveal whether thresholds are too aggressive or lenient.
