#!/usr/bin/env python3
"""EC297 offline multi-epoch EC296 rotation-lineage verifier."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec297_anchor_lineage.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
