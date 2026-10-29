#!/usr/bin/env python3
"""EC329 strictly read-only isolated dual offline review ledger comparator."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'construction'))
from offline_ledger_comparison.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
