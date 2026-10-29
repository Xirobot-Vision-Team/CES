#!/usr/bin/env python3
"""EC366 isolated offline Ed25519 institution root-provenance auditor."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from root_provenance.operator import main
if __name__=='__main__':raise SystemExit(main())
