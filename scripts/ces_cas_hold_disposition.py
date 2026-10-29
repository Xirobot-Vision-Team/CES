#!/usr/bin/env python3
"""EC327 standalone strictly read-only ninth offline disposition verifier."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'construction'))
from ec327_offline_hold_disposition.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
