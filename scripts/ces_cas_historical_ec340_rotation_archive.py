#!/usr/bin/env python3
"""EC387 fixed air-gapped read-only original EC340 epoch rotation receiver."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec387_historical_rotation.operator import main
if __name__=='__main__':raise SystemExit(main())
