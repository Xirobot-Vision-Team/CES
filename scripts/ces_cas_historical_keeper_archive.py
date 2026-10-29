#!/usr/bin/env python3
"""EC382 fixed offline SHA-pinned original keeper/EC347 readback receiver."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from historical_keeper.operator import main
if __name__=='__main__':raise SystemExit(main())
