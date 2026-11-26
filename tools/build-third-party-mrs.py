#!/usr/bin/env python3
"""Build public MRS providers; local-only entries are never published by CI."""
import json
from pathlib import Path
from mrs_build import build

ROOT = Path(__file__).resolve().parent.parent
SOURCES = json.loads((ROOT / "tools/third-party-mrs-sources.json").read_text())
build(ROOT, [s for s in SOURCES if s.get("distribution", "public") == "public"])
