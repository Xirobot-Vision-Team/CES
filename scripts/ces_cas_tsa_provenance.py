#!/usr/bin/env python3
"""EC351 read-only signed origin-source statement and genuine DER OCSP verifier."""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'construction'))
from ec351_tsa_provenance.operator import main

if __name__=='__main__':
    raise SystemExit(main())
