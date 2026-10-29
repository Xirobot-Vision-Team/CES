#!/usr/bin/env python3
"""EC367 isolated offline dual institution-status distribution witnesses."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from witness_distribution.operator import main
if __name__=='__main__':raise SystemExit(main())
