#!/usr/bin/env python3
"""EC334 standalone unsigned first-hop inventory, map and read-only audit."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from portable_source_inventory.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
