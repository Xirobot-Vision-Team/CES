#!/usr/bin/env python3
"""Read-only offline EC406 CLI: never creates original evidence or signatures."""
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from ec406_custody_witness.operator import main

if __name__=='__main__':
    raise SystemExit(main())
