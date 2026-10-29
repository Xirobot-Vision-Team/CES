#!/usr/bin/env python3
"""EC361 fixed, isolated offline directory-consistency and observer-gossip audit."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from directory_consistency.operator import main
if __name__=='__main__':raise SystemExit(main())
