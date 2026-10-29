#!/usr/bin/env python3
"""EC345 separate offline signing candidates and read-only audit entry point."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from disclosure_challenge.operator import main
if __name__=='__main__':
    raise SystemExit(main())
