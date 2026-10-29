#!/usr/bin/env python3
"""EC372 fixed caller-pinned read-only historic root revocation entrypoint."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from historical_authority.operator import main
if __name__=='__main__':raise SystemExit(main())
