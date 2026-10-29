#!/usr/bin/env python3
"""EC288 fixed entry for independently governed original EC225 sandbox host."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from ec288_delivery_send_host.operator import main
if __name__=='__main__':
    raise SystemExit(main())
