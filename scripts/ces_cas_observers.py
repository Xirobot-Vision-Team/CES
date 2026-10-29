#!/usr/bin/env python3
"""EC312 two independent signed CAS observer windows, strictly offline."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from dual_observer_reconciliation.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
