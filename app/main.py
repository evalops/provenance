"""Application entrypoint for the Provenance service."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.routers import analysis, analytics, governance
from app.telemetry import configure_metrics, shutdown_metrics
from app.dependencies import get_event_sink


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_metrics()
    yield
    sink = get_event_sink()
    if hasattr(sink, "close"):
        sink.close()
    shutdown_metrics()


def create_app() -> FastAPI:
    app = FastAPI(
        title="Provenance & Risk Analytics",
        description="Tracks agent attribution, computes risk analytics, and enforces governance policies.",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.include_router(analysis.router)
    app.include_router(analytics.router)
    app.include_router(governance.router)

    @app.get("/healthz", tags=["health"])
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    return app


app = create_app()
