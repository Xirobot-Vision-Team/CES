#!/usr/bin/env python3
"""EC340: separated local candidate signers and read-only signed-root verifier."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from issuer_root_rotation.operator import main
if __name__=='__main__':
    raise SystemExit(main())
