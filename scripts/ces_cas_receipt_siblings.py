#!/usr/bin/env python3
"""EC325 offline sibling local receipt conflict dispute case CLI."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec325_offline_receipt_siblings.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
