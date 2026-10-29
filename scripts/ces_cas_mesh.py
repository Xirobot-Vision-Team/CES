#!/usr/bin/env python3
"""EC314 read-only Ed25519 original signed multi-window intersection mesh."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec314_window_mesh.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
