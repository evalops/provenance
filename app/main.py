"""Application entrypoint for the Provenance service."""

from __future__ import annotations

from fastapi import FastAPI

from app.routers import analysis, analytics, governance
from app.telemetry import configure_metrics
from app.dependencies import get_event_sink


def create_app() -> FastAPI:
    configure_metrics()
    app = FastAPI(
        title="Provenance & Risk Analytics",
        description="Tracks agent attribution, computes risk analytics, and enforces governance policies.",
        version="0.1.0",
    )

    app.include_router(analysis.router)
    app.include_router(analytics.router)
    app.include_router(governance.router)

    @app.get("/healthz", tags=["health"])
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    @app.on_event("shutdown")
    async def shutdown_telemetry() -> None:
        sink = get_event_sink()
        if hasattr(sink, "close"):
            sink.close()

    return app


app = create_app()
