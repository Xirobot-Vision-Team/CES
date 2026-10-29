#!/usr/bin/env python3
"""EC401 standalone isolated offline read-only RFC6960 OCSP evidence receiver."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'construction'))
from ec401_ocsp_evidence.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
