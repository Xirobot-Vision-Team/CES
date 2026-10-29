#!/usr/bin/env python3
"""EC298 two independently pinned EC297 histories: offline signed fork evidence."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec298_anchor_conflicts.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
