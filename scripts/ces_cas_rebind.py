#!/usr/bin/env python3
"""EC317 lossless SHA-preserving original-source transport CLI (not signing)."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from original_rebinding.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
