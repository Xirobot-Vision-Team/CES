#!/usr/bin/env python3
"""EC383 fixed offline receiver-only authenticated challenger/copy provenance."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec383_historical_readback.operator import main
if __name__=='__main__':raise SystemExit(main())
