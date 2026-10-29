#!/usr/bin/env python3
"""EC384 fixed receiver-only original Ed25519 EC344/EC345 audit."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from historical_offer.operator import main
if __name__=='__main__':raise SystemExit(main())
