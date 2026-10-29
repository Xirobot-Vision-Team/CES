#!/usr/bin/env python3
"""EC309: offline read-only audit of a SECOND independently signed CAS readback."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from cas_readback.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
