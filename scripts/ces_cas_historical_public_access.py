#!/usr/bin/env python3
"""EC404 offline original signed public-access receipt verifier."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'construction'))
from public_access.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
