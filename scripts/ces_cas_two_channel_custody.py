#!/usr/bin/env python3
"""EC356 fixed offline signed two-institution-channel original custody, READ ONLY."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from custody.operator import main
if __name__=='__main__':raise SystemExit(main())
