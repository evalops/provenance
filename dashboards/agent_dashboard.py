"""Streamlit dashboard for visualising agent analytics."""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pandas as pd
import streamlit as st


API_BASE_URL = os.getenv("PROVENANCE_DASHBOARD_API", "http://localhost:8000/v1")
EVENTS_PATH = os.getenv("PROVENANCE_DASHBOARD_EVENTS", "data/timeseries_events.jsonl")


@st.cache_data(show_spinner=False)
def fetch_summary(metric: str, time_window: str) -> pd.DataFrame:
    url = f"{API_BASE_URL}/analytics/summary"
    params = {"metric": metric, "time_window": time_window, "group_by": "agent_id"}
    response = httpx.get(url, params=params, timeout=30.0)
    response.raise_for_status()
    data = response.json()["result"]["data"]
    if not data:
        return pd.DataFrame()
    return pd.DataFrame(data)


@st.cache_data(show_spinner=False)
def fetch_behavior(time_window: str) -> pd.DataFrame:
    url = f"{API_BASE_URL}/analytics/agents/behavior"
    response = httpx.get(url, params={"time_window": time_window}, timeout=30.0)
    response.raise_for_status()
    report = response.json()["report"]
    snapshots = report["snapshots"]
    if not snapshots:
        return pd.DataFrame()
    frame = pd.json_normalize(snapshots)
    frame["window_start"] = pd.to_datetime(report["window_start"])
    frame["window_end"] = pd.to_datetime(report["window_end"])
    return frame


@st.cache_data(show_spinner=False)
def load_timeseries_events(days: int) -> pd.DataFrame:
    path = Path(EVENTS_PATH)
    if not path.exists():
        return pd.DataFrame()
    frame = pd.read_json(path, lines=True)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    cutoff = pd.Timestamp.utcnow() - pd.Timedelta(days=days)
    frame = frame[frame["timestamp"] >= cutoff]
    return frame.explode("agent_metrics").reset_index(drop=True)


def prepare_trends(frame: pd.DataFrame) -> pd.DataFrame:
    if frame.empty:
        return frame
    metrics = pd.json_normalize(frame["agent_metrics"])
    combined = pd.concat([frame[["timestamp"]].reset_index(drop=True), metrics], axis=1)
    combined["timestamp"] = pd.to_datetime(combined["timestamp"])
    combined.sort_values("timestamp", inplace=True)
    return combined


def main() -> None:
    st.set_page_config(page_title="Agent Provenance Analytics", layout="wide")
    st.title("Agent Provenance & Risk Dashboard")
    time_window = st.sidebar.selectbox("Time window", ["1d", "3d", "7d", "14d", "30d"], index=2)
    trend_days = st.sidebar.slider("Trend lookback (days)", min_value=1, max_value=60, value=14)

    col1, col2, col3 = st.columns(3)

    with col1:
        st.subheader("Risk rate per 1k lines")
        risk_df = fetch_summary("risk_rate", time_window)
        if risk_df.empty:
            st.info("No data yet.")
        else:
            st.bar_chart(risk_df.set_index("agent_id")["value"])

    with col2:
        st.subheader("Provenance coverage (%)")
        prov_df = fetch_summary("provenance_coverage", time_window)
        if prov_df.empty:
            st.info("No data yet.")
        else:
            st.bar_chart(prov_df.set_index("agent_id")["value"])

    with col3:
        st.subheader("Code churn rate (%)")
        churn_df = fetch_summary("code_churn_rate", time_window)
        if churn_df.empty:
            st.info("No data yet.")
        else:
            st.bar_chart(churn_df.set_index("agent_id")["value"])

    st.subheader("Agent behavior snapshot")
    behavior_df = fetch_behavior(time_window)
    if behavior_df.empty:
        st.info("No behavior data yet.")
    else:
        st.dataframe(
            behavior_df[
                [
                    "agent_id",
                    "code_volume",
                    "churn_lines",
                    "churn_rate",
                    "avg_line_complexity",
                    "top_vulnerability_categories",
                ]
            ]
        )

        st.caption(
            f"Window {behavior_df['window_start'].iloc[0]} → {behavior_df['window_end'].iloc[0]} | Updated {datetime.utcnow().isoformat()}"
        )

    st.subheader("Trend analysis (timeseries events)")
    events_df = load_timeseries_events(trend_days)
    trend_df = prepare_trends(events_df)
    if trend_df.empty:
        st.info("Timeseries event log not available or empty. Configure PROVENANCE_DASHBOARD_EVENTS to enable trends.")
    else:
        for metric in ["code_volume", "churn_rate", "avg_line_complexity", "max_line_complexity"]:
            chart_df = trend_df.pivot(index="timestamp", columns="agent_id", values=metric)
            st.line_chart(chart_df, height=240)


if __name__ == "__main__":
    main()
