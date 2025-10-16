"""Streamlit dashboard for visualising agent analytics."""

from __future__ import annotations

import os
from datetime import datetime

import httpx
import pandas as pd
import streamlit as st


API_BASE_URL = os.getenv("PROVENANCE_DASHBOARD_API", "http://localhost:8000/v1")


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


def main() -> None:
    st.set_page_config(page_title="Agent Provenance Analytics", layout="wide")
    st.title("Agent Provenance & Risk Dashboard")
    time_window = st.sidebar.selectbox("Time window", ["1d", "3d", "7d", "14d", "30d"], index=2)

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


if __name__ == "__main__":
    main()
