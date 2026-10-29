#!/usr/bin/env python3
"""EC300 fixed standalone offline doubly signed gossip session client."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from bilateral_gossip.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
