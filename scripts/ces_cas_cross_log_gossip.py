#!/usr/bin/env python3
"""EC354 offline SHA-pinned signed gossip importer; READ ONLY, no signer."""
from __future__ import annotations
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from gossip.operator import main
if __name__=='__main__':raise SystemExit(main())
