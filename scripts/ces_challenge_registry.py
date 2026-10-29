#!/usr/bin/env python3
"""EC304 offline signed spent-challenge registry; see construction EC304."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from ec304_challenge_registry.operator import main
if __name__=='__main__':raise SystemExit(main())
