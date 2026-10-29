#!/usr/bin/env python3
"""EC376 exact fixed historical genuine EC354/EC355 disclosure read-only CLI."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from historical_disclosure.operator import main
if __name__=='__main__':raise SystemExit(main())
