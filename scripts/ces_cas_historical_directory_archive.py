#!/usr/bin/env python3
"""EC371 caller-pinned receiver historic directory archive fixed entrypoint."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from ec371_historical_archive.operator import main
if __name__=='__main__':raise SystemExit(main())
