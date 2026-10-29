#!/usr/bin/env python3
"""EC296 explicit, optional, offline four-signer EC295 key rotation."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'construction'))
from ec296_anchor_rotation.operator import main
if __name__ == '__main__':
    raise SystemExit(main())
