#!/usr/bin/env python3
"""EC363 fixed isolated, signed offline publisher history/readback CLI."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec363_source_history.operator import main
if __name__=='__main__':raise SystemExit(main())
