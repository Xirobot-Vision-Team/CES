#!/usr/bin/env python3
"""EC355 fixed offline original-byte disclosure verifier; READ ONLY, no signer."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec355_disclosure.operator import main
if __name__=='__main__':raise SystemExit(main())
