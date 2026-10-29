#!/usr/bin/env python3
"""EC301 standalone offline offer, recipient ack and full-journal verification."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from offline_handoff.operator import main
if __name__=='__main__':raise SystemExit(main())
