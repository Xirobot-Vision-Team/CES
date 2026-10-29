#!/usr/bin/env python3
"""EC330 standalone replayable offline review comparison report (no network)."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'construction'))
from replayable_comparison_report.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
