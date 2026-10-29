#!/usr/bin/env python3
"""EC365 isolated offline directory authority dual signature audit."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from directory_lineage.operator import main
if __name__=='__main__':raise SystemExit(main())
