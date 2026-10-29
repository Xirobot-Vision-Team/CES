#!/usr/bin/env python3
"""EC344 standalone receiver-controlled candidate signing / pinned read-only audit."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from receiver_visibility.operator import main
if __name__=='__main__':
    raise SystemExit(main())
