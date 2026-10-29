#!/usr/bin/env python3
"""EC343 standalone owner-private signers / verified read-only receiver."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from hold_receipts.operator import main
if __name__=='__main__':
    raise SystemExit(main())
