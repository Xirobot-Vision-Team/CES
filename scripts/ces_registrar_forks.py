#!/usr/bin/env python3
"""EC307 independently pinned same-parent registrar fork evidence (offline)."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from registrar_forks.operator import main

if __name__=='__main__':
    raise SystemExit(main())
