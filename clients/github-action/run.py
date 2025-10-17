from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path

import httpx


def collect_diff(workdir: Path, base_sha: str, head_sha: str) -> list[dict]:
    cmd = [
        "git",
        "diff",
        "--unified=0",
        f"{base_sha}..{head_sha}",
    ]
    result = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, check=False)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"git diff failed: {result.stderr}")
    diff = result.stdout
    changed_lines: list[dict] = []
    file_path = None
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            file_path = line[6:]
        elif line.startswith("@@") and file_path:
            parts = line.split()
            if len(parts) >= 3:
                hunk = parts[2]
                if "+" in hunk:
                    _, coords = hunk.split("+")
                    start, *_ = coords.split(",")
                    try:
                        start_line = int(start)
                    except ValueError:
                        continue
                    changed_lines.append(
                        {
                            "file_path": file_path,
                            "line_number": start_line,
                            "change_type": "modified",
                            "content": None,
                            "attribution": {"agent_id": ""},
                        }
                    )
    return changed_lines


def submit_analysis(
    api_url: str,
    api_token: str,
    payload: dict,
) -> dict:
    headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
    resp = httpx.post(f"{api_url}/v1/analysis", json=payload, headers=headers, timeout=30.0)
    resp.raise_for_status()
    return resp.json()


def poll_decision(api_url: str, api_token: str, analysis_id: str, *, timeout_s: int = 300) -> dict:
    headers = {"Authorization": f"Bearer {api_token}"}
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        resp = httpx.get(f"{api_url}/v1/analysis/{analysis_id}", headers=headers, timeout=15.0)
        resp.raise_for_status()
        data = resp.json()
        status = data["status"]
        if status == "completed":
            return data
        if status == "failed":
            raise RuntimeError(f"Analysis failed: {data}")
        time.sleep(5)
    raise TimeoutError("Timed out waiting for analysis decision")


def main() -> None:
    parser = argparse.ArgumentParser(description="Submit diff to Provenance API")
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--api-token", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--pr", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--workdir", default=".")
    args = parser.parse_args()

    workdir = Path(args.workdir)
    changed_lines = collect_diff(workdir, args.base_sha, args.head_sha)
    payload = {
        "repo": args.repo,
        "pr_number": args.pr,
        "base_sha": args.base_sha,
        "head_sha": args.head_sha,
        "branch": None,
        "provenance_data": {
            "metadata": {},
            "changed_lines": changed_lines,
        },
    }

    response = submit_analysis(args.api_url, args.api_token, payload)
    analysis_id = response["analysis_id"]
    decision = poll_decision(args.api_url, args.api_token, analysis_id)
    write_response_path = os.getenv("PROVENANCE_WRITE_RESPONSE_PATH")
    if write_response_path:
        out_path = Path(write_response_path)
        if not out_path.parent.exists():
            out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(decision, indent=2))
    decision_info = decision.get("decision") or {}
    outcome_value = decision_info.get("outcome") or decision.get("status")
    if isinstance(outcome_value, str) and outcome_value.lower() == "block":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
