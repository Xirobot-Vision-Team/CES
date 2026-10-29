#!/usr/bin/env python3
"""EC339 issuer-only local signer, and separate receiver all-original verifier."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'construction'))
from offline_authority.operator import main
if __name__=='__main__':
    raise SystemExit(main())
