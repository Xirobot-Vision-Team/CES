#!/usr/bin/env python3
"""EC332 fixed local read-only compare of two pinned EC331 report sets."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'construction'))
from ec332_pinned_report_set_delta.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
