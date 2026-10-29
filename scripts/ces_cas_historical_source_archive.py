#!/usr/bin/env python3
"""Fixed, isolated offline EC379 old EC351 source attestation receiver CLI."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from historical_source.operator import main
if __name__=='__main__':raise SystemExit(main())
