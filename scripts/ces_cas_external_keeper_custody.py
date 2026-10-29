#!/usr/bin/env python3
"""EC348 imported independent keeper original claims; no private-key writer."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from external_custody.operator import main
if __name__=='__main__':
    raise SystemExit(main())
