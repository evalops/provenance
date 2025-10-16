"""Domain data models for the provenance analytics service."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ChangeType(str, Enum):
    """Categorisation for how a line changed in the diff."""

    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


class FindingStatus(str, Enum):
    """Lifecycle states for a detector finding."""

    OPEN = "open"
    SUPPRESSED = "suppressed"
    REMEDIATED = "remediated"


class PolicyOutcome(str, Enum):
    """Possible outcomes for a policy decision."""

    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"


class SeverityLevel(str, Enum):
    """Severity scale for detector findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AgentIdentity(BaseModel):
    """Represents the logical identity of a code producing agent."""

    agent_id: str = Field(..., description="Unique identifier for the agent, e.g. claude-3-opus.")
    agent_version: Optional[str] = Field(
        None, description="Optional semantic version identifier for the agent runtime."
    )


class ProvenanceAttribution(BaseModel):
    """Metadata that binds a line-level change to an agent session."""

    agent: AgentIdentity
    agent_session_id: Optional[str] = Field(
        None, description="Opaque session identifier provided by the agent runtime."
    )
    commit_sha: Optional[str] = Field(
        None, description="Commit SHA that introduced the change when available."
    )
    provenance_marker: Optional[str] = Field(
        None,
        description="Raw provenance marker string (commit trailer, PR metadata, etc.) for traceability.",
    )


class ChangedLine(BaseModel):
    """Denominator fact representing one changed line in a pull request diff."""

    analysis_id: str
    repo_id: str
    pr_number: str
    head_sha: str
    file_path: str
    line_number: int
    change_type: ChangeType
    timestamp: datetime
    branch: Optional[str] = None
    author_identity: Optional[str] = None
    language: Optional[str] = None
    content: Optional[str] = Field(
        None,
        description="Optional snippet of the changed line for evidence; may be omitted depending on retention policy.",
    )
    attribution: ProvenanceAttribution


class Suppression(BaseModel):
    """Represents a manual suppression of a finding."""

    suppressed_at: datetime
    reason: str
    approver_identity: str


class Finding(BaseModel):
    """A detector result tied to a specific change."""

    finding_id: str
    analysis_id: str
    repo_id: str
    pr_number: str
    file_path: str
    line_number: int
    rule_key: str
    rule_version: str
    category: str
    severity: SeverityLevel
    engine_name: str
    message: str
    detected_at: datetime
    status: FindingStatus = FindingStatus.OPEN
    attribution: ProvenanceAttribution
    suppression: Optional[Suppression] = None
    remediated_at: Optional[datetime] = None
    remediation_analysis_id: Optional[str] = None


class PolicyDecision(BaseModel):
    """Represents a governance decision for a given analysis."""

    decision_id: str
    analysis_id: str
    repo_id: str
    pr_number: str
    decided_at: datetime
    outcome: PolicyOutcome
    rationale: str
    risk_summary: dict = Field(
        default_factory=dict,
        description="Opaque dict with metric snapshots used to reach the decision.",
    )
    provenance_status: str = Field(
        ...,
        description="Summary of provenance coverage state used in the policy evaluation.",
    )
    policy_version: str
    evidence_links: list[str] = Field(default_factory=list)


class AnalysisStatus(str, Enum):
    """Processing lifecycle states for an analysis request."""

    RECEIVED = "received"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class AnalysisRecord(BaseModel):
    """Aggregate record for one analysis execution."""

    analysis_id: str
    status: AnalysisStatus
    repo_id: str
    pr_number: str
    base_sha: str
    head_sha: str
    created_at: datetime
    updated_at: datetime
    provenance_inputs: dict = Field(default_factory=dict)
    error_message: Optional[str] = None
