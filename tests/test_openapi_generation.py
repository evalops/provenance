import json
import sys
from pathlib import Path

import scripts.generate_openapi as generator


def test_generate_openapi(tmp_path, monkeypatch):
    output = tmp_path / "schema.json"
    monkeypatch.setattr(sys, "argv", ["generate_openapi", "--output", str(output)])
    generator.main()
    assert output.exists()
    schema = json.loads(output.read_text(encoding="utf-8"))
    assert schema["info"]["title"] == "Provenance & Risk Analytics"
