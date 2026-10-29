#!/usr/bin/env python3
"""EC381 fixed offline RFC3161 original-evidence entry."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from historical_channel.operator import main
if __name__=='__main__':raise SystemExit(main())
