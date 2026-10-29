#!/usr/bin/env python3
"""EC299 fixed standalone offline two-witness observation entrypoint."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from witness_consistency.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
