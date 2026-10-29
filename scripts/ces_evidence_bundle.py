#!/usr/bin/env python3
"""EC302 standalone import/export/verify-only portable EC301 signed proof archive."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from portable_bundle.operator import main
if __name__=='__main__':raise SystemExit(main())
