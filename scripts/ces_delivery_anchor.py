#!/usr/bin/env python3
"""EC295 offline external delivery audit anchor and rollback comparison tool."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from ec295_delivery_anchor.operator import main
if __name__=='__main__':
    raise SystemExit(main())
