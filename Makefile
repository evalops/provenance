.PHONY: setup test compile run docs dashboard

setup:
	uv sync --all-extras

test:
	uv run -- pytest

compile:
	uv run -- python -m compileall app

run:
	uv run -- uvicorn app.main:app --reload

docs:
	uv run -- python scripts/generate_openapi.py

dashboard:
	uv run --group dashboard -- streamlit run dashboards/agent_dashboard.py
