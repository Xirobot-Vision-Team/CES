#!/usr/bin/env python3
"""EC313 complete offline intersection of two EC312 original signed windows."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from window_intersection.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
