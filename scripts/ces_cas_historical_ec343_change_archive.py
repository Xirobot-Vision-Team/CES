#!/usr/bin/env python3
"""EC385 fixed receiver-only SHA-pinned original EC342/EC343 audit."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec385_historical_change.operator import main
if __name__=='__main__':raise SystemExit(main())
