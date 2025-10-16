"""Generate and persist the OpenAPI schema for the Provenance service."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from fastapi.openapi.utils import get_openapi

from app.main import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate OpenAPI schema")
    parser.add_argument(
        "--output",
        default="openapi.json",
        help="Path to write the OpenAPI schema (default: openapi.json)",
    )
    args = parser.parse_args()

    app = create_app()
    schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
        description=app.description,
    )
    output_path = Path(args.output)
    output_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    print(f"OpenAPI schema written to {output_path}")


if __name__ == "__main__":
    main()
