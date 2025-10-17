.PHONY: setup test compile run docs dashboard clickhouse-up

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

clickhouse-up:
	docker run --rm -p 8123:8123 -p 9000:9000 \
		-v $(PWD)/infrastructure/clickhouse/schema.sql:/docker-entrypoint-initdb.d/schema.sql \
		clickhouse/clickhouse-server:latest
