#!/usr/bin/env python3
"""EC323 standalone portable original-case and seventh ACK capsule CLI."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from composite_fork_capsule.operator import main
if __name__=='__main__':
    raise SystemExit(main())
