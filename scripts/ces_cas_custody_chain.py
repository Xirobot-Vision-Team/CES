#!/usr/bin/env python3
"""EC338 separate local role signer and fixed read-only verification CLI."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from ec338_independent_custody.operator import main
if __name__=='__main__':
    raise SystemExit(main())
