#!/usr/bin/env python3
"""EC337 private sender / receiver standalone; unified mode only inspects."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from ec337_airgap_transport.operator import main
if __name__=='__main__':
    raise SystemExit(main())
