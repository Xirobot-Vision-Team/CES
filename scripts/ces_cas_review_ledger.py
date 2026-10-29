#!/usr/bin/env python3
"""EC328 standalone offline unsigned-ledger preparer and strict read-only verifier."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT/'construction'))
from ec328_offline_review_ledger.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
