#!/usr/bin/env python3
"""EC316 separate offline dual-custodian signing and read-only verification CLI."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec316_dual_custodian_checkpoint.operator import main

if __name__ == '__main__':
    raise SystemExit(main())
