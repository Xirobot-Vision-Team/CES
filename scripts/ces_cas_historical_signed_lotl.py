#!/usr/bin/env python3
"""EC410 fixed read-only isolated LOTL original-byte operator."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from lotl_authority.operator import main
if __name__=='__main__':
    raise SystemExit(main())
