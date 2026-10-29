#!/usr/bin/env python3
"""EC303 offline recipient signature after imported EC302 evidence verified."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from ec303_receiver_ack.operator import main
if __name__=='__main__':raise SystemExit(main())
