#!/usr/bin/env python3
"""EC342 separate signing tool / receiver; unified console verifies only."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from conflict_hold.operator import main
if __name__=='__main__':
    raise SystemExit(main())
