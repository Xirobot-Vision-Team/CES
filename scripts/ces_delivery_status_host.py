#!/usr/bin/env python3
"""EC293 fixed independent original EC226 DeliveryStatus Readback host."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from ec293_delivery_status_host.operator import main
if __name__=='__main__':
    raise SystemExit(main())
