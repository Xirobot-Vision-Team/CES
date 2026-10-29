#!/usr/bin/env python3
"""Isolated EC408 dual-window issuer/delegate-signed OCSP original receiver."""
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'construction'))
from institutional_ocsp.operator import main

if __name__=='__main__':
    raise SystemExit(main())
