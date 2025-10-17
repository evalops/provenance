CREATE DATABASE IF NOT EXISTS provenance;

CREATE TABLE IF NOT EXISTS provenance.analysis_events
(
    event_time DateTime DEFAULT now(),
    payload JSON
)
ENGINE = MergeTree
ORDER BY (event_time);

CREATE TABLE IF NOT EXISTS provenance.findings
(
    analysis_id String,
    repo_id String,
    pr_number String,
    rule_key String,
    severity String,
    detected_at DateTime,
    payload JSON
)
ENGINE = MergeTree
ORDER BY (analysis_id, rule_key, detected_at);

CREATE TABLE IF NOT EXISTS provenance.review_events
(
    repo_id String,
    pr_number String,
    agent_id String,
    recorded_at DateTime DEFAULT now(),
    payload JSON
)
ENGINE = MergeTree
ORDER BY (repo_id, pr_number, recorded_at);
