#!/usr/bin/env python3
"""EC321 standalone lossless signed registrar fork case transport."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from ec321_fork_case_transport.operator import main
if __name__=='__main__':
    raise SystemExit(main())
