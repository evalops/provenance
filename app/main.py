"""Application entrypoint for the Provenance service."""

from __future__ import annotations

from fastapi import FastAPI
from app.routers import analysis, analytics, governance


def create_app() -> FastAPI:
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

    return app


app = create_app()
