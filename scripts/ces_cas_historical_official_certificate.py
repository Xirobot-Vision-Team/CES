#!/usr/bin/env python3
"""EC399 isolated offline external X.509 publisher and CRL verifier."""
from __future__ import annotations
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'construction'))
from official_certificate.operator import main
if __name__=='__main__':raise SystemExit(main())
