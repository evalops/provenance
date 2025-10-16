"""Utilities for generating identifiers used across the service."""

from __future__ import annotations

import uuid


def new_analysis_id() -> str:
    return f"an_{uuid.uuid4().hex}"


def new_finding_id() -> str:
    return f"fd_{uuid.uuid4().hex}"


def new_decision_id() -> str:
    return f"pd_{uuid.uuid4().hex}"
