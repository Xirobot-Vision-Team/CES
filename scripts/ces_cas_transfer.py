#!/usr/bin/env python3
"""EC318 independent two-party signed original EC317 transfer CLI."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec318_bilateral_transfer_receipt.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
